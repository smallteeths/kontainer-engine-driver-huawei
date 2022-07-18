package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cnrancher/huaweicloud-sdk/cce"
	"github.com/cnrancher/huaweicloud-sdk/common"
	"github.com/cnrancher/huaweicloud-sdk/elb"
	"github.com/cnrancher/huaweicloud-sdk/network"
	"github.com/pkg/errors"
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

type state struct {
	AccessKey             string
	SecretKey             string
	ClusterName           string
	DisplayName           string
	Description           string
	ProjectID             string
	Region                string
	ClusterType           string
	ClusterFlavor         string
	ClusterVersion        string
	ClusterBillingMode    int64
	ClusterLabels         map[string]string
	ContainerNetworkMode  string
	ContainerNetworkCidr  string
	VpcID                 string
	SubnetID              string
	VipSubnetID           string
	HighwaySubnet         string
	AuthenticatingProxyCa string
	ClusterID             string
	ExternalServerEnabled bool
	ClusterEIPID          string
	ClusterJobID          string
	NodeConfig            *common.NodeConfig
	AuthMode              string
	APIServerELBID        string
	PoolID                string

	ClusterInfo types.ClusterInfo
}

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
	cceClient := cce.NewClient(baseClient)
	networkClient := network.NewClient(baseClient)
	elbClient := elb.NewClient(baseClient)
	cleanUpResources := []string{}
	clusterinfo := types.ClusterInfo{}
	var eipInfo *common.EipInfo
	var elbInfo *common.LoadBalancerInfo
	var listenerInfo *common.ELBListenerInfo
	//resource cleanup defer
	defer func() {
		if rtnerr != nil && len(cleanUpResources) != 0 {
			deleteResources(ctx, state, cleanUpResources)
		}
	}()

	if state.VpcID == "" {
		cleanUpResources = append(cleanUpResources, "vpc")
		if _, err := createVPC(ctx, networkClient, &state); err != nil {
			return nil, err
		}
	}
	if state.SubnetID == "" {
		cleanUpResources = append(cleanUpResources, "subnet")
		if _, err := createSubnet(ctx, networkClient, &state); err != nil {
			return nil, err
		}
	}

	if state.ExternalServerEnabled {
		if state.ClusterEIPID != "" {
			if eipInfo, err = networkClient.GetEIP(ctx, state.ClusterEIPID); err != nil {
				return nil, err
			}
		}
		if state.APIServerELBID == "" {
			cleanUpResources = append(cleanUpResources, "elb")
			if elbInfo, err = createELB(ctx, elbClient, eipInfo, &state); err != nil {
				return nil, err
			}
			state.APIServerELBID = elbInfo.Loadbalancer.ID
		} else {
			elbInfo, err = elbClient.GetLoadBalancer(ctx, state.APIServerELBID)
			if err != nil {
				return nil, err
			}
		}
		listeners, err := elbClient.GetListeners(ctx)
		if err != nil {
			return nil, err
		}
		for _, listener := range (*listeners).Listeners {
			if listener.Listener.LoadbalancerID == elbInfo.Loadbalancer.ID && listener.Listener.Port == 5443 {
				listenerInfo = &listener
				break
			}
		}
		if listenerInfo == nil {
			if listenerInfo, err = createListener(ctx, elbClient, &state); err != nil {
				return nil, err
			}
		}
	}

	var cceClusterInfo *common.ClusterInfo
	cleanUpResources = append(cleanUpResources, "cluster")
	if cceClusterInfo, err = createCluster(ctx, cceClient, &state); err != nil {
		return nil, err
	}

	if err := createNodes(ctx, cceClient, &state); err != nil {
		return nil, err
	}

	if state.ExternalServerEnabled {
		addresses, err := createProxyDaemonSets(ctx, cceClient, cceClusterInfo, &state)
		if err != nil {
			return nil, err
		}
		if _, err := addBackends(ctx, listenerInfo.Listener.ID, elbClient, addresses, &state); err != nil {
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
	cceClient := cce.NewClient(baseClient)

	cluster, err := cceClient.GetCluster(ctx, state.ClusterID)
	if err != nil {
		return nil, err
	}
	if logrus.GetLevel() == logrus.DebugLevel {
		jsondata, _ := json.Marshal(cluster)
		logrus.Debugf("cluster info %s", string(jsondata))
	}

	cert, err := cceClient.GetClusterCert(ctx, state.ClusterID)
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

	for _, cluster := range cert.Clusters {
		switch cluster.Name {
		case "internalCluster":
			internalServer = cluster.Cluster.Server
			clusterInfo.RootCaCertificate = cluster.Cluster.CertificateAuthorityData
		}
	}

	// The "internalServer" is internal api-server url.
	// You can only access internal api-server url with the CA cert.
	// The CA cert only signed for internal api-server url and can't be updated through api
	clusterInfo.Endpoint = internalServer

	clusterInfo.Status = cluster.Status.Phase
	clusterInfo.ClientKey = cert.Users[0].User.ClientKeyData
	clusterInfo.ClientCertificate = cert.Users[0].User.ClientCertificateData
	clusterInfo.Username = cert.Users[0].Name

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

func (state *state) validate() error {
	if state.ClusterName == "" {
		return fmt.Errorf("cluster name is required")
	}

	if state.AccessKey == "" {
		return fmt.Errorf("access key is required")
	}

	if state.SecretKey == "" {
		return fmt.Errorf("secret key is required")
	}

	if state.ProjectID == "" {
		return fmt.Errorf("project id is required")
	}

	if state.ClusterType == "" {
		return fmt.Errorf("cluster type is required")
	}

	if state.ClusterFlavor == "" {
		return fmt.Errorf("cluster flavor is required")
	}

	if state.ClusterVersion == "" {
		return fmt.Errorf("cluster version is required")
	}

	if state.NodeConfig.NodeCount <= 0 {
		return errors.New("cluster node count must be more than 0")
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

func getState(info *types.ClusterInfo) (state, error) {
	state := state{}

	err := json.Unmarshal([]byte(info.Metadata["state"]), &state)
	if err != nil {
		logrus.Errorf("Error encountered while marshalling state: %v", err)
	}

	return state, err
}

func getHuaweiBaseClient(s state) *common.Client {
	return common.NewClient(
		s.AccessKey,
		s.SecretKey,
		common.DefaultAPIEndpoint,
		s.Region,
		s.ProjectID,
	)
}

func deleteResources(ctx context.Context, state state, sources []string) {
	baseClient := getHuaweiBaseClient(state)
	networkClient := network.NewClient(baseClient)
	cceClient := cce.NewClient(baseClient)
	elbClient := elb.NewClient(baseClient)
	for _, source := range sources {
		switch {
		case source == "vpc" && state.VpcID != "":
			logrus.Infof("cleaning up vpc %s", state.VpcID)
			if err := networkClient.DeleteVPC(ctx, state.VpcID); err != nil {
				logrus.WithError(err).Warn("error cleaning up vpc")
			}
		case source == "subnet" && state.SubnetID != "":
			logrus.Infof("cleaning up subnet %s", state.SubnetID)
			if err := networkClient.DeleteSubnet(ctx, state.SubnetID); err != nil {
				logrus.WithError(err).Warnf("error cleaning up subnet %s", state.SubnetID)
			}
		case source == "cluster" && state.ClusterID != "":
			logrus.Infof("cleaning up cluster %s", state.ClusterID)
			if err := cceClient.DeleteCluster(ctx, state.ClusterID); err != nil {
				logrus.WithError(err).Warnf("error cleaning up cluster %s", state.ClusterID)
			}
		case source == "elb" && state.APIServerELBID != "":
			logrus.Infof("cleaning up elb %s", state.APIServerELBID)
			// Query ELB listeners
			lbInfo, _ := elbClient.GetLoadBalancer(ctx, state.APIServerELBID)
			listenerIDList := lbInfo.Loadbalancer.Listeners
			// Release ELB listeners
			emptyListenerBody := map[string]interface{}{
				"listener": map[string]interface{}{
					"default_pool_id": nil,
				},
			}
			for _, listenerIDObj := range listenerIDList {
				if _, err := elbClient.UpdateListener(ctx, listenerIDObj.ID, emptyListenerBody); err != nil {
					logrus.WithError(err).Warnf("error cleaning up cluster %s(update listener:%s)", state.ClusterID, listenerIDObj.ID)
				}
			}
			// Delete ELB listeners
			for _, listenerIDObj := range listenerIDList {
				if err := elbClient.DeleteListener(ctx, listenerIDObj.ID); err != nil {
					logrus.WithError(err).Warnf("error cleaning up cluster %s(delete listener:%s)", state.ClusterID, listenerIDObj.ID)
				}
			}
			// Query Pools
			poolIDList := lbInfo.Loadbalancer.Pools
			for _, poolIDObj := range poolIDList {
				pool, _ := elbClient.GetBackendGroup(ctx, poolIDObj.ID)
				hlID := pool.Pool.HealthmonitorID
				// Delete HealthMonitor
				if err := elbClient.DeleteHealthcheck(ctx, hlID); err != nil {
					logrus.WithError(err).Warnf("error cleaning up cluster %s(healthmonitor:%s)", state.ClusterID, hlID)
				}
				poolID := pool.Pool.ID
				members := pool.Pool.Members
				// Delete Members
				for _, memberIDObj := range members {
					if err := elbClient.RemoveBackend(ctx, poolID, memberIDObj.ID); err != nil {
						logrus.WithError(err).Warnf("error cleaning up cluster %s(backend:%s-%s)", state.ClusterID, poolID, memberIDObj.ID)
					}
				}
			}
			// Delete Pools
			for _, poolIDObj := range poolIDList {
				if err := elbClient.RemoveBackendGroup(ctx, poolIDObj.ID); err != nil {
					logrus.WithError(err).Warnf("error cleaning up cluster %s(backendgroup:%s)", state.ClusterID, poolIDObj.ID)
				}
			}
			// Delete ELB
			if err := elbClient.DeleteLoadBalancer(ctx, state.APIServerELBID); err != nil {
				logrus.WithError(err).Warnf("error cleaning up cluster %s(elb:%s)", state.ClusterID, state.APIServerELBID)
			}
		case source == "eip" && state.ClusterEIPID != "":
			info := common.EipAssocArg{
				Port: common.PortDesc{},
			}
			if _, err := networkClient.UpdateEIP(ctx, state.ClusterEIPID, &info); err != nil {
				continue
			}
		}
	}
}

func getClusterRequestFromState(state state) *common.ClusterInfo {
	clusterReq := &common.ClusterInfo{
		Kind:       "cluster",
		APIVersion: "v3",
		MetaData: common.MetaInfo{
			Name:   state.DisplayName,
			Labels: state.ClusterLabels,
		},
		Spec: common.SpecInfo{
			ClusterType: state.ClusterType,
			Flavor:      state.ClusterFlavor,
			K8sVersion:  state.ClusterVersion,
			HostNetwork: &common.NetworkInfo{
				Vpc:           state.VpcID,
				Subnet:        state.SubnetID,
				HighwaySubnet: state.HighwaySubnet,
			},
			ContainerNetwork: &common.ContainerNetworkInfo{
				Mode: state.ContainerNetworkMode,
				Cidr: state.ContainerNetworkCidr,
			},
			BillingMode: state.ClusterBillingMode,
			Authentication: common.Authentication{
				Mode: state.AuthMode,
			},
		},
	}
	if state.AuthMode == "authenticating_proxy" {
		clusterReq.Spec.Authentication.AuthenticatingProxy.Ca = state.AuthenticatingProxyCa
	}
	return clusterReq
}

func storeState(info *types.ClusterInfo, state state) error {
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
	cceClient := cce.NewClient(getHuaweiBaseClient(state))
	nodeList, err := cceClient.GetNodes(ctx, state.ClusterID)
	if err != nil {
		return err
	}
	existedNodeNum := int64(len(nodeList.Items))
	if count > existedNodeNum {
		nodes := getNodeRequirement(state, count-existedNodeNum)
		if _, err := cceClient.AddNode(ctx, state.ClusterID, nodes); err != nil {
			return fmt.Errorf("error adding nodes to cluster: %v", err)
		}
	} else if count < existedNodeNum {
		if deletedCount, err := cceClient.DeleteNodes(ctx, state.ClusterID, int(existedNodeNum-count)); err != nil {
			return fmt.Errorf("error deleting nodes from cluster: %v, deleted %d", err, deletedCount)
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
