package driver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cce/v3/model"
	elb_model "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/elb/v2/model"
	"github.com/pkg/errors"
	"github.com/rancher/kontainer-engine-driver-huawei/cce"
	"github.com/rancher/kontainer-engine-driver-huawei/common"
	"github.com/rancher/kontainer-engine-driver-huawei/elb"
	"github.com/rancher/kontainer-engine-driver-huawei/network"
	"github.com/rancher/rancher/pkg/kontainer-engine/drivers/util"
	"github.com/rancher/rancher/pkg/kontainer-engine/types"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	retries          = 5
	pollInterval     = 30
	defaultNamespace = "cattle-system"
)

type CCEDriver struct {
	driverCapabilities types.Capabilities
}

func (d *CCEDriver) ETCDSave(ctx context.Context, clusterInfo *types.ClusterInfo, opts *types.DriverOptions, snapshotName string) error {
	return fmt.Errorf("ETCD backup operations are not implemented")
}

func (d *CCEDriver) ETCDRestore(ctx context.Context, clusterInfo *types.ClusterInfo, opts *types.DriverOptions, snapshotName string) (*types.ClusterInfo, error) {
	return nil, fmt.Errorf("ETCD backup operations are not implemented")
}

func (d *CCEDriver) ETCDRemoveSnapshot(ctx context.Context, clusterInfo *types.ClusterInfo, opts *types.DriverOptions, snapshotName string) error {
	return fmt.Errorf("ETCD backup operations are not implemented")
}

// GetDriverCreateOptions returns cli flags that are used in create
func (d *CCEDriver) GetDriverCreateOptions(ctx context.Context) (*types.DriverFlags, error) {
	driverFlag := types.DriverFlags{
		Options: make(map[string]*types.Flag),
	}
	fillCreateOptions(&driverFlag)

	return &driverFlag, nil
}

// GetDriverUpdateOptions returns cli flags that are used in update
func (d *CCEDriver) GetDriverUpdateOptions(ctx context.Context) (*types.DriverFlags, error) {
	driverFlag := types.DriverFlags{
		Options: make(map[string]*types.Flag),
	}
	driverFlag.Options["description"] = &types.Flag{
		Type:  types.StringType,
		Usage: "An optional description of this cluster",
	}

	return &driverFlag, nil
}

// Create creates the cluster. clusterInfo is only set when we are retrying a failed or interrupted create
func (d *CCEDriver) Create(ctx context.Context, opts *types.DriverOptions, clusterInfo *types.ClusterInfo) (info *types.ClusterInfo, rtnerr error) {
	logrus.Info("creating new cluster")
	state, err := getStateFromOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("error parsing state: %v", err)
	}
	baseClient := getHuaweiBaseClient(state)
	cceClient := cce.GetCCEServiceClient(baseClient)
	networkClient := network.NewNetWorkClient(baseClient)
	elbClient := elb.NewElbClient(baseClient)
	eipClient := network.NewEipClient(baseClient)
	cleanUpResources := []string{}
	clusterinfo := types.ClusterInfo{}
	var elbInfo *elb_model.CreateLoadbalancerResponse
	var listenerInfo *elb_model.ListenerResp
	//resource cleanup defer
	defer func() {
		if rtnerr != nil && len(cleanUpResources) != 0 {
			deleteResources(ctx, state, cleanUpResources)
		}
	}()

	if state.VpcID == "" {
		cleanUpResources = append(cleanUpResources, "vpc")
		if _, err := network.CreateVPC(ctx, networkClient, &state); err != nil {
			return nil, err
		}
	}
	if state.SubnetID == "" {
		cleanUpResources = append(cleanUpResources, "subnet")
		if _, err := network.CreateSubnet(ctx, networkClient, &state); err != nil {
			return nil, err
		}
	}

	if state.ExternalServerEnabled {
		if state.ClusterEIPID != "" {
			if _, err = network.ShowPublicip(eipClient, state.ClusterEIPID); err != nil {
				return nil, err
			}
		}
		if state.APIServerELBID == "" {
			cleanUpResources = append(cleanUpResources, "elb")
			if elbInfo, err = elb.CreateELB(elbClient, &state); err != nil {
				return nil, err
			}
			state.APIServerELBID = elbInfo.Loadbalancer.Id
		} else {
			if _, err = elb.GetLoadBalancer(elbClient, state.APIServerELBID); err != nil {
				return nil, err
			}
		}
		listeners, err := elb.ListListeners(elbClient)
		if err != nil {
			return nil, err
		}
		for _, listener := range *listeners.Listeners {
			hasLoadbalancerID := false
			for _, loadbalancer := range listener.Loadbalancers {
				if loadbalancer.Id == elbInfo.Loadbalancer.Id {
					hasLoadbalancerID = true
				}
			}
			if hasLoadbalancerID && listener.ProtocolPort == 5443 {
				listenerInfo = &listener
				break
			}
		}
		if listenerInfo == nil {
			if listenerInfo, err = elb.CreateListener(elbClient, &state); err != nil {
				return nil, err
			}
		}
	}

	var cceClusterInfo *model.ShowClusterResponse
	cleanUpResources = append(cleanUpResources, "cluster")
	if cceClusterInfo, err = cce.CreateCluster(ctx, cceClient, &state); err != nil {
		return nil, err
	}

	if _, err := cce.CreateNodes(ctx, *cceClusterInfo.Metadata.Uid, cceClient, &state, int32(state.NodeConfig.NodeCount)); err != nil {
		return nil, err
	}

	if state.ExternalServerEnabled {
		addresses, err := createProxyDaemonSets(ctx, cceClient, cceClusterInfo)
		if err != nil {
			return nil, err
		}
		if _, err := elb.AddBackends(listenerInfo.Id, elbClient, addresses, &state); err != nil {
			return nil, err
		}
		// clusterinfo.Endpoint = fmt.Sprintf("https://%s:5443", elbInfo.Loadbalancer.VIPAddress)
	}

	err = storeState(&clusterinfo, state)
	if err != nil {
		return nil, err
	}
	return &clusterinfo, nil
}

// Update updates the cluster
func (d *CCEDriver) Update(ctx context.Context, clusterInfo *types.ClusterInfo, opts *types.DriverOptions) (rtn *types.ClusterInfo, rtnerr error) {
	defer func() {
		if rtnerr != nil {
			logrus.WithError(rtnerr).Info("update return error")
		}
	}()
	logrus.Info("Starting update")
	state, err := getState(clusterInfo)
	if err != nil {
		return nil, err
	}

	newState, err := getStateFromOptions(opts)
	if err != nil {
		return nil, err
	}
	newState.ClusterID = state.ClusterID

	if newState.NodeConfig.NodeCount != state.NodeConfig.NodeCount {
		if err := d.setNodeCount(ctx, clusterInfo, newState.NodeConfig.NodeCount); err != nil {
			return nil, err
		}
	}

	state.NodeConfig.NodeCount = newState.NodeConfig.NodeCount
	logrus.Info("update cluster success")
	return clusterInfo, storeState(clusterInfo, state)
}

// PostCheck does post action after provisioning
func (d *CCEDriver) PostCheck(ctx context.Context, clusterInfo *types.ClusterInfo) (*types.ClusterInfo, error) {
	logrus.Infof("Starting post-check")
	state, err := getState(clusterInfo)
	if err != nil {
		return nil, err
	}
	baseClient := getHuaweiBaseClient(state)
	cceClient := cce.GetCCEServiceClient(baseClient)

	cluster, err := cce.ShowCluster(cceClient, state.ClusterID)
	if err != nil {
		return nil, err
	}
	if logrus.GetLevel() == logrus.DebugLevel {
		jsondata, _ := json.Marshal(cluster)
		logrus.Debugf("cluster info %s", string(jsondata))
	}

	cert, err := cce.GetClusterCert(cluster, cceClient)
	if err != nil {
		return nil, err
	}
	if logrus.GetLevel() == logrus.DebugLevel {
		jsondata, _ := json.Marshal(cert)
		logrus.Debugf("cert info %s", string(jsondata))
	}

	clusterInfo.Version = state.ClusterVersion
	clusterInfo.NodeCount = state.NodeConfig.NodeCount

	var internalServer string

	for _, cluster := range *cert.Clusters {
		switch *cluster.Name {
		case "internalCluster":
			internalServer = *cluster.Cluster.Server
			clusterInfo.RootCaCertificate = *cluster.Cluster.CertificateAuthorityData
		}
	}

	// The "internalServer" is internal api-server url.
	// You can only access internal api-server url with the CA cert.
	// The CA cert only signed for internal api-server url and can't be updated through api
	clusterInfo.Endpoint = internalServer
	users := *cert.Users
	clientKey := users[0].User.ClientKeyData
	clientCertificate := users[0].User.ClientCertificateData
	name := users[0].Name
	clusterInfo.Status = *cluster.Status.Phase
	clusterInfo.ClientKey = *clientKey
	clusterInfo.ClientCertificate = *clientCertificate
	clusterInfo.Username = *name

	clientset, err := getClientSet(ctx, clusterInfo)
	if err != nil {
		return nil, fmt.Errorf("error creating clientset: %v", err)
	}

	failureCount := 0

	for {
		clusterInfo.ServiceAccountToken, err = util.GenerateServiceAccountToken(clientset)

		if err == nil {
			logrus.Info("service account token generated successfully")
			break
		} else {
			logrus.WithError(err).Warnf("error creating service account")
			if failureCount < retries {
				logrus.Infof("service account token generation failed, retries left: %v", retries-failureCount)
				failureCount = failureCount + 1

				time.Sleep(pollInterval * time.Second)
			} else {
				logrus.Error("retries exceeded, failing post-check")
				return nil, err
			}
		}
	}
	logrus.Info("post-check completed successfully")
	logrus.Debugf("info: %v", *clusterInfo)

	return clusterInfo, storeState(clusterInfo, state)
}

// Remove removes the cluster
func (d *CCEDriver) Remove(ctx context.Context, clusterInfo *types.ClusterInfo) error {
	state, err := getState(clusterInfo)
	if err != nil {
		return err
	}
	deleteResources(ctx, state, []string{"elb", "cluster", "eip"})
	return nil
}

func (d *CCEDriver) GetVersion(ctx context.Context, clusterInfo *types.ClusterInfo) (*types.KubernetesVersion, error) {
	state, err := getState(clusterInfo)
	if err != nil {
		return nil, err
	}
	version := &types.KubernetesVersion{Version: state.ClusterVersion}
	return version, nil
}
func (d *CCEDriver) SetVersion(ctx context.Context, clusterInfo *types.ClusterInfo, version *types.KubernetesVersion) error {
	return errors.New("not supported")
}
func (d *CCEDriver) GetClusterSize(ctx context.Context, clusterInfo *types.ClusterInfo) (*types.NodeCount, error) {
	state, err := getState(clusterInfo)
	if err != nil {
		return nil, err
	}
	count := &types.NodeCount{Count: state.NodeConfig.NodeCount}
	return count, nil
}
func (d *CCEDriver) SetClusterSize(ctx context.Context, clusterInfo *types.ClusterInfo, count *types.NodeCount) error {
	return d.setNodeCount(ctx, clusterInfo, count.GetCount())
}

func (d *CCEDriver) GetCapabilities(ctx context.Context) (*types.Capabilities, error) {
	return &d.driverCapabilities, nil
}

func (d *CCEDriver) GetK8SCapabilities(ctx context.Context, opts *types.DriverOptions) (*types.K8SCapabilities, error) {
	return &types.K8SCapabilities{
		L4LoadBalancer: &types.LoadBalancerCapabilities{
			Enabled: false,
		},
		NodePoolScalingSupported: false,
	}, nil
}

func getValueFromDriverOptions(driverOptions *types.DriverOptions, optionType string, keys ...string) interface{} {
	switch optionType {
	case types.IntType:
		for _, key := range keys {
			if value, ok := driverOptions.IntOptions[key]; ok {
				return value
			}
		}
		return int64(0)
	case types.StringType:
		for _, key := range keys {
			if value, ok := driverOptions.StringOptions[key]; ok {
				return value
			}
		}
		return ""
	case types.BoolType:
		for _, key := range keys {
			if value, ok := driverOptions.BoolOptions[key]; ok {
				return value
			}
		}
		return false
	case types.StringSliceType:
		for _, key := range keys {
			if value, ok := driverOptions.StringSliceOptions[key]; ok {
				return value
			}
		}
		return &types.StringSlice{}
	}
	return nil
}

func NewDriver() types.Driver {
	driver := &CCEDriver{
		driverCapabilities: types.Capabilities{
			Capabilities: make(map[int64]bool),
		},
	}

	driver.driverCapabilities.AddCapability(types.GetVersionCapability)
	driver.driverCapabilities.AddCapability(types.GetClusterSizeCapability)
	driver.driverCapabilities.AddCapability(types.SetClusterSizeCapability)

	return driver
}

func getState(info *types.ClusterInfo) (common.State, error) {
	state := common.State{}

	err := json.Unmarshal([]byte(info.Metadata["state"]), &state)
	if err != nil {
		logrus.Errorf("Error encountered while marshalling state: %v", err)
	}

	return state, err
}

func getHuaweiBaseClient(s common.State) *common.Client {
	return common.NewClient(
		s.AccessKey,
		s.SecretKey,
		s.Region,
		s.ProjectID,
	)
}

func deleteResources(ctx context.Context, state common.State, sources []string) {
	baseClient := getHuaweiBaseClient(state)
	networkClient := network.NewNetWorkClient(baseClient)
	networkClientV2 := network.NewEipV2Client(baseClient)
	cceClient := cce.GetCCEServiceClient(baseClient)
	elbClient := elb.NewElbClient(baseClient)
	for _, source := range sources {
		switch {
		case source == "vpc" && state.VpcID != "":
			logrus.Infof("cleaning up vpc %s", state.VpcID)
			if _, err := network.DeleteVPC(networkClient, state.VpcID); err != nil {
				logrus.WithError(err).Warn("error cleaning up vpc")
			}
		case source == "subnet" && state.SubnetID != "" && state.VpcID != "":
			logrus.Infof("cleaning up subnet %s", state.SubnetID)
			if _, err := network.DeleteSubnet(networkClient, state.VpcID, state.SubnetID); err != nil {
				logrus.WithError(err).Warnf("error cleaning up subnet %s", state.SubnetID)
			}
		case source == "eip" && state.ClusterEIPID != "":
			if _, err := network.UpdatePublicip(networkClientV2, state.ClusterEIPID); err != nil {
				continue
			}
		case source == "cluster" && state.ClusterID != "":
			if state.APIServerELBID != "" {
				logrus.Infof("cleaning up elb %s", state.APIServerELBID)
				// Query ELB listeners
				lbInfo, _ := elb.GetLoadBalancer(elbClient, state.APIServerELBID)
				// Query Pools
				poolIDList := lbInfo.Loadbalancer.Pools
				for _, poolIDObj := range poolIDList {
					pool, _ := elb.ShowPool(elbClient, poolIDObj.Id)
					hlID := pool.Pool.HealthmonitorId
					// Delete HealthMonitor
					if hlID != "" {
						logrus.Infof("cleaning up HealthmonitorId %s", hlID)
						if _, err := elb.DeleteHealthcheck(elbClient, hlID); err != nil {
							logrus.WithError(err).Warnf("error cleaning up cluster %s(healthmonitor:%s)", state.ClusterID, hlID)
						}
					}
					poolID := pool.Pool.Id
					members := pool.Pool.Members
					// Delete Members
					for _, memberIDObj := range members {
						logrus.Infof("cleaning up member %s", memberIDObj.Id)
						if _, err := elb.DeleteMember(elbClient, poolID, memberIDObj.Id); err != nil {
							logrus.WithError(err).Warnf("error cleaning up cluster %s(backend:%s-%s)", state.ClusterID, poolID, memberIDObj.Id)
						}
					}
				}
				// Delete Pools
				for _, poolIDObj := range poolIDList {
					logrus.Infof("cleaning up poolIDObj %s", poolIDObj.Id)
					if _, err := elb.DeletePool(elbClient, poolIDObj.Id); err != nil {
						logrus.WithError(err).Warnf("error cleaning up cluster %s(backendgroup:%s)", state.ClusterID, poolIDObj.Id)
					}
				}
				listenerIDList := lbInfo.Loadbalancer.Listeners
				// Release ELB listeners
				for _, listenerIDObj := range listenerIDList {
					if _, err := elb.UpdateListener(elbClient, listenerIDObj.Id); err != nil {
						logrus.WithError(err).Warnf("error cleaning up cluster %s(update listener:%s)", state.ClusterID, listenerIDObj.Id)
					}
				}
				// Delete ELB listeners
				for _, listenerIDObj := range listenerIDList {
					if _, err := elb.DeleteListener(elbClient, listenerIDObj.Id); err != nil {
						logrus.WithError(err).Warnf("error cleaning up cluster %s(delete listener:%s)", state.ClusterID, listenerIDObj.Id)
					}
				}
				// Delete ELB
				if _, err := elb.DeleteLoadBalancer(elbClient, state.APIServerELBID); err != nil {
					logrus.Infof("cleaning up DeleteLoadBalancer %s", state.APIServerELBID)
					logrus.WithError(err).Warnf("error cleaning up cluster %s(elb:%s)", state.ClusterID, state.APIServerELBID)
				}
			}
			logrus.Infof("cleaning up cluster %s", state.ClusterID)
			if rtn, err := cce.DeleteCluster(cceClient, state.ClusterID); err != nil {
				ok, _, err := common.WaitForJobReadyV3(ctx, cceClient, 20*time.Second, 30*time.Minute, *rtn.Status.JobID)
				if !ok {
					logrus.WithError(err).Warnf("error cleaning up cluster %s", state.ClusterID)
				}
			}
		}
	}
}

func storeState(info *types.ClusterInfo, state common.State) error {
	data, err := json.Marshal(state)

	if err != nil {
		return err
	}

	if info.Metadata == nil {
		info.Metadata = map[string]string{}
	}

	info.Metadata["state"] = string(data)

	return nil
}

func (d *CCEDriver) setNodeCount(ctx context.Context, clusterInfo *types.ClusterInfo, count int64) error {
	logrus.Info("setting cluster node count")
	state, err := getState(clusterInfo)
	if err != nil {
		return err
	}
	baseClient := getHuaweiBaseClient(state)
	cceClient := cce.GetCCEServiceClient(baseClient)
	request := &model.ListNodesRequest{}
	request.ClusterId = state.ClusterID
	nodeList, err := cceClient.ListNodes(request)
	if err != nil {
		return err
	}
	existedNodeNum := int64(len(*nodeList.Items))
	if count > existedNodeNum {
		if _, err := cce.CreateNodes(ctx, request.ClusterId, cceClient, &state, int32(count-existedNodeNum)); err != nil {
			return fmt.Errorf("error adding nodes to cluster: %v", err)
		}
	} else if count < existedNodeNum {
		index := existedNodeNum - count
		nodeListItems := *nodeList.Items
		deleteNodeList := nodeListItems[:index]
		if err := cce.DeleteNodes(ctx, state.ClusterID, cceClient, deleteNodeList); err != nil {
			return fmt.Errorf("error deleting nodes from cluster: %v", err)
		}
	}
	logrus.Info("set cluster node count success")
	return nil
}

func (d *CCEDriver) RemoveLegacyServiceAccount(ctx context.Context, clusterInfo *types.ClusterInfo) error {
	clientSet, err := getClientSet(ctx, clusterInfo)
	if err != nil {
		return err
	}

	return util.DeleteLegacyServiceAccountAndRoleBinding(clientSet)
}

func getClientSet(ctx context.Context, clusterInfo *types.ClusterInfo) (*kubernetes.Clientset, error) {
	capem, err := base64.StdEncoding.DecodeString(clusterInfo.RootCaCertificate)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CA: %v", err)
	}

	key, err := base64.StdEncoding.DecodeString(clusterInfo.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode client key: %v", err)
	}

	certdata, err := base64.StdEncoding.DecodeString(clusterInfo.ClientCertificate)
	if err != nil {
		return nil, fmt.Errorf("failed to decode client cert: %v", err)
	}

	host := clusterInfo.Endpoint
	if !strings.HasPrefix(host, "https://") {
		host = fmt.Sprintf("https://%s", host)
	}

	config := &rest.Config{
		Host: host,
		TLSClientConfig: rest.TLSClientConfig{
			CAData:   capem,
			KeyData:  key,
			CertData: certdata,
		},
	}

	return kubernetes.NewForConfig(config)
}
