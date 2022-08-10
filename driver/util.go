package driver

import (
	"bytes"
	"context"
	"net/url"
	"strings"
	"text/template"

	huawei_cce "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cce/v3"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cce/v3/model"
	"github.com/rancher/kontainer-engine-driver-huawei/cce"
	"github.com/rancher/kontainer-engine-driver-huawei/common"
	"github.com/rancher/rancher/pkg/kontainer-engine/types"
	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var configTemplate, _ = template.New("nginx-template").Parse(nginxConfigTemplate)

func fillCreateOptions(driverFlag *types.DriverFlags) {
	driverFlag.Options["display-name"] = &types.Flag{
		Type:  types.StringType,
		Usage: "the name of the cluster that should be displayed to the user",
	}
	//base client parameters
	driverFlag.Options["project-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "the ID of your project to use when creating a cluster",
	}
	driverFlag.Options["region"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The region to launch the cluster",
		Value: "cn-north-1",
	}
	driverFlag.Options["access-key"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The CCE Access Key ID to use",
	}
	driverFlag.Options["secret-key"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The CCE Secret Key associated with the Client ID",
	}
	//cluster parameters
	driverFlag.Options["cluster-type"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The cluster type, VirtualMachine or BareMetal",
		Value: "VirtualMachine",
	}
	driverFlag.Options["cluster-flavor"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The cluster flavor",
		Value: "cce.s2.small",
	}
	driverFlag.Options["cluster-billing-mode"] = &types.Flag{
		Type:  types.IntType,
		Usage: "The bill mode of the cluster",
		Value: "0",
	}
	driverFlag.Options["description"] = &types.Flag{
		Type:  types.StringType,
		Usage: "An optional description of this cluster",
	}
	driverFlag.Options["master-version"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The kubernetes master version",
		Value: "v1.9.10-r0",
	}
	driverFlag.Options["node-count"] = &types.Flag{
		Type:  types.IntType,
		Usage: "The number of nodes to create in this cluster",
		Value: "3",
	}
	driverFlag.Options["vpc-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The id of existing vpc",
	}
	driverFlag.Options["subnet-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The id of existing subnet",
	}
	driverFlag.Options["highway-subnet"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The id of existing highway subnet when the cluster-type is BareMetal",
	}
	driverFlag.Options["container-network-mode"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The network mode of container",
		Value: "overlay_l2",
	}
	driverFlag.Options["container-network-cidr"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The network cidr of container",
		Value: "172.16.0.0/16",
	}
	driverFlag.Options["cluster-labels"] = &types.Flag{
		Type:  types.StringSliceType,
		Usage: "The map of Kubernetes labels (key/value pairs) to be applied to cluster",
	}
	driverFlag.Options["authentiaction-mode"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The Authentication Mode for cce cluster. rbac or authenticating_proxy, default to rbac",
		Value: "rbac",
	}
	driverFlag.Options["authenticating-proxy-ca"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The CA for authenticating proxy, it is required if authentiaction-mode is authenticating_proxy",
	}
	driverFlag.Options["cluster-eip-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The id of cluster eip. If set, it means that this cluster should be accessed from this eip",
	}
	driverFlag.Options["external-server-enabled"] = &types.Flag{
		Type:  types.BoolType,
		Usage: "To enable cluster elastic IP",
	}
	driverFlag.Options["api-server-elb-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The id of elb which use to proxy api server",
	}
	//node parameters
	//node management
	driverFlag.Options["node-flavor"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The node flavor",
		Value: "s3.large.2",
	}
	driverFlag.Options["available-zone"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The available zone which the nodes in",
		Value: "cn-north-1a",
	}
	driverFlag.Options["node-labels"] = &types.Flag{
		Type:  types.StringSliceType,
		Usage: "The map of Kubernetes labels (key/value pairs) to be applied to each node",
	}
	driverFlag.Options["billing-mode"] = &types.Flag{
		Type:  types.IntType,
		Usage: "The bill mode of the node",
		Value: "0",
	}
	driverFlag.Options["bms-period-type"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The period type",
		Value: "month",
	}
	driverFlag.Options["bms-period-num"] = &types.Flag{
		Type:  types.IntType,
		Usage: "The number of period",
		Value: "1",
	}
	driverFlag.Options["bms-is-auto-renew"] = &types.Flag{
		Type:  types.StringType,
		Usage: "If the period is auto renew",
		Value: "false",
	}
	//node common
	driverFlag.Options["node-operation-system"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The operation system of nodes",
		Value: "EulerOS 2.2",
	}
	driverFlag.Options["ssh-key"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The name of ssh key-pair",
	}
	driverFlag.Options["user-name"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The user name to log in the host. This flag will be ignored if ssh-key is set.",
	}
	driverFlag.Options["password"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The password to log in the host This flag will be ignored if ssh-key is set.",
	}
	//node data
	driverFlag.Options["root-volume-size"] = &types.Flag{
		Type:  types.IntType,
		Usage: "Size of the system disk attached to each node",
		Value: "40",
	}
	driverFlag.Options["root-volume-type"] = &types.Flag{
		Type:  types.StringType,
		Usage: "Type of the system disk attached to each node",
		Value: "SATA",
	}
	driverFlag.Options["data-volume-size"] = &types.Flag{
		Type:  types.IntType,
		Usage: "Size of the data disk attached to each node",
		Value: "100",
	}
	driverFlag.Options["data-volume-type"] = &types.Flag{
		Type:  types.StringType,
		Usage: "Type of the data disk attached to each node",
		Value: "SATA",
	}
	//node network
	driverFlag.Options["eip-ids"] = &types.Flag{
		Type:  types.StringSliceType,
		Usage: "The list of the exist EIPs",
	}
	driverFlag.Options["eip-count"] = &types.Flag{
		Type:  types.IntType,
		Usage: "The number of eips to be created",
		Value: "3",
	}
	driverFlag.Options["eip-type"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The type of bandwidth",
		Value: "5-bgp",
	}
	driverFlag.Options["eip-charge-mode"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The charge mode of the bandwidth",
		Value: "traffic",
	}
	driverFlag.Options["eip-bandwidth-size"] = &types.Flag{
		Type:  types.IntType,
		Usage: "The size of bandwidth",
		Value: "10",
	}
	driverFlag.Options["eip-share-type"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The share type of bandwidth",
		Value: "PER",
	}
	driverFlag.Options["vip-subnet-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "VipSubnetID",
	}
	driverFlag.Options["kubernetes-svc-ip-range"] = &types.Flag{
		Type:  types.StringType,
		Usage: "KubernetesSvcIPRange",
	}
}

func getStateFromOptions(driverOptions *types.DriverOptions) (common.State, error) {
	state := common.State{
		NodeConfig: &common.NodeConfig{
			NodeLabels: map[string]string{},
			PublicIP: common.PublicIP{
				Eip: &common.Eip{},
			},
		},
		ClusterLabels: map[string]string{},
	}
	state.ClusterName = getValueFromDriverOptions(driverOptions, types.StringType, "name").(string)
	state.DisplayName = getValueFromDriverOptions(driverOptions, types.StringType, "display-name", "displayName").(string)
	state.ProjectID = getValueFromDriverOptions(driverOptions, types.StringType, "project-id", "projectId").(string)
	state.Region = getValueFromDriverOptions(driverOptions, types.StringType, "region").(string)
	state.Description = getValueFromDriverOptions(driverOptions, types.StringType, "description").(string)
	state.ClusterType = getValueFromDriverOptions(driverOptions, types.StringType, "cluster-type", "clusterType").(string)
	state.ClusterFlavor = getValueFromDriverOptions(driverOptions, types.StringType, "cluster-flavor", "clusterFlavor").(string)
	state.ClusterVersion = getValueFromDriverOptions(driverOptions, types.StringType, "master-version", "masterVersion").(string)
	state.AccessKey = getValueFromDriverOptions(driverOptions, types.StringType, "access-key", "accessKey").(string)
	state.SecretKey = getValueFromDriverOptions(driverOptions, types.StringType, "secret-key", "secretKey").(string)
	state.ClusterBillingMode = getValueFromDriverOptions(driverOptions, types.IntType, "cluster-billing-mode", "clusterBillingMode").(int64)
	state.VpcID = getValueFromDriverOptions(driverOptions, types.StringType, "vpc-id", "vpcId").(string)
	state.SubnetID = getValueFromDriverOptions(driverOptions, types.StringType, "subnet-id", "subnetId").(string)
	state.ContainerNetworkMode = getValueFromDriverOptions(driverOptions, types.StringType, "container-network-mode", "containerNetworkMode").(string)
	state.ContainerNetworkCidr = getValueFromDriverOptions(driverOptions, types.StringType, "container-network-cidr", "containerNetworkCidr").(string)
	state.KubernetesSvcIPRange = getValueFromDriverOptions(driverOptions, types.StringType, "kubernetes-svc-ip-range", "kubernetesSvcIpRange").(string)
	state.HighwaySubnet = getValueFromDriverOptions(driverOptions, types.StringType, "highway-subnet", "highwaySubnet").(string)
	state.NodeConfig.NodeFlavor = getValueFromDriverOptions(driverOptions, types.StringType, "node-flavor", "nodeFlavor").(string)
	state.NodeConfig.AvailableZone = getValueFromDriverOptions(driverOptions, types.StringType, "available-zone", "availableZone").(string)
	state.NodeConfig.SSHName = getValueFromDriverOptions(driverOptions, types.StringType, "ssh-key", "sshKey").(string)
	state.NodeConfig.RootVolumeSize = getValueFromDriverOptions(driverOptions, types.IntType, "root-volume-size", "rootVolumeSize").(int64)
	state.NodeConfig.RootVolumeType = getValueFromDriverOptions(driverOptions, types.StringType, "root-volume-type", "rootVolumeType").(string)
	state.NodeConfig.DataVolumeSize = getValueFromDriverOptions(driverOptions, types.IntType, "data-volume-size", "dataVolumeSize").(int64)
	state.NodeConfig.DataVolumeType = getValueFromDriverOptions(driverOptions, types.StringType, "data-volume-type", "dataVolumeType").(string)
	state.NodeConfig.BillingMode = getValueFromDriverOptions(driverOptions, types.IntType, "billing-mode", "billingMode").(int64)
	state.NodeConfig.NodeCount = getValueFromDriverOptions(driverOptions, types.IntType, "node-count", "nodeCount").(int64)
	state.NodeConfig.PublicIP.Count = getValueFromDriverOptions(driverOptions, types.IntType, "eip-count", "eipCount").(int64)
	state.NodeConfig.PublicIP.Eip.Iptype = getValueFromDriverOptions(driverOptions, types.StringType, "eip-type", "eipType").(string)
	state.NodeConfig.PublicIP.Eip.Bandwidth.Size = getValueFromDriverOptions(driverOptions, types.IntType, "eip-bandwidth-size", "eipBandwidthSize").(int64)
	state.NodeConfig.PublicIP.Eip.Bandwidth.ShareType = getValueFromDriverOptions(driverOptions, types.StringType, "eip-share-type", "eipShareType").(string)
	state.NodeConfig.PublicIP.Eip.Bandwidth.ChargeMode = getValueFromDriverOptions(driverOptions, types.StringType, "eip-charge-mode", "eipChargeMode").(string)
	state.NodeConfig.NodeOperationSystem = getValueFromDriverOptions(driverOptions, types.StringType, "node-operation-system", "nodeOperationSystem").(string)
	state.NodeConfig.ExtendParam.BMSPeriodType = getValueFromDriverOptions(driverOptions, types.StringType, "bms-period-type", "bmsPeriodType").(string)
	state.NodeConfig.ExtendParam.BMSPeriodNum = getValueFromDriverOptions(driverOptions, types.IntType, "bms-period-num", "bmsPeriodNum").(int64)
	state.NodeConfig.ExtendParam.BMSIsAutoRenew = getValueFromDriverOptions(driverOptions, types.StringType, "bms-is-auto-renew", "bmsIsAutoRenew").(string)
	state.NodeConfig.UserPassword.UserName = getValueFromDriverOptions(driverOptions, types.StringType, "user-name", "userName").(string)
	state.NodeConfig.UserPassword.Password = getValueFromDriverOptions(driverOptions, types.StringType, "password").(string)
	state.AuthenticatingProxyCa = getValueFromDriverOptions(driverOptions, types.StringType, "authenticating-proxy-ca", "authenticatingProxyCa").(string)
	state.ExternalServerEnabled = getValueFromDriverOptions(driverOptions, types.BoolType, "external-server-enabled", "externalServerEnabled").(bool)
	state.ClusterEIPID = getValueFromDriverOptions(driverOptions, types.StringType, "cluster-eip-id", "clusterEipId").(string)
	state.AuthMode = getValueFromDriverOptions(driverOptions, types.StringType, "authentiaction-mode", "authentiactionMode").(string)
	state.APIServerELBID = getValueFromDriverOptions(driverOptions, types.StringType, "api-server-elb-id", "apiServerELBId").(string)

	state.VipSubnetID = getValueFromDriverOptions(driverOptions, types.StringType, "vip-subnet-id", "vipSubnetId").(string)

	eipIDs := getValueFromDriverOptions(driverOptions, types.StringSliceType, "eip-ids", "eipIds").(*types.StringSlice)
	for _, eipID := range eipIDs.Value {
		logrus.Debugf("Eip: %s", eipID)
		state.NodeConfig.PublicIP.Ids = append(state.NodeConfig.PublicIP.Ids, eipID)
	}
	nodeLabels := getValueFromDriverOptions(driverOptions, types.StringSliceType, "node-labels", "nodeLabels").(*types.StringSlice)
	for _, nodeLabel := range nodeLabels.Value {
		kv := strings.Split(nodeLabel, "=")
		if len(kv) == 2 {
			state.NodeConfig.NodeLabels[kv[0]] = kv[1]
		}
	}
	clusterLabels := getValueFromDriverOptions(driverOptions, types.StringSliceType, "labels").(*types.StringSlice)
	for _, clusterLabel := range clusterLabels.Value {
		kv := strings.Split(clusterLabel, "=")
		if len(kv) == 2 {
			state.ClusterLabels[kv[0]] = kv[1]
		}
	}
	logrus.Debugf("state is %#v", state)
	logrus.Debugf("node config is %#v", *state.NodeConfig)
	return state, state.Validate()
}

func createDefaultNamespace(ctx context.Context, client kubernetes.Interface) error {
	if _, err := client.CoreV1().Namespaces().Create(ctx, &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: defaultNamespace,
		},
	}, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func createNginxConfig(ctx context.Context, client kubernetes.Interface, apiserver string) (*v1.ConfigMap, error) {
	logrus.Info("creating nginx config for cluster apiserver proxy..")
	entry := nginxConfig{
		APIServerHost: apiserver,
	}
	var configBuf bytes.Buffer
	if err := configTemplate.Execute(&configBuf, entry); err != nil {
		return nil, err
	}
	rtn := v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "proxy-conf",
			Namespace: defaultNamespace,
		},
		Data: map[string]string{
			"nginx.conf": configBuf.String(),
		},
	}
	if _, err := client.CoreV1().ConfigMaps(defaultNamespace).Create(ctx, &rtn, metav1.CreateOptions{}); err != nil {
		return nil, err
	}
	logrus.Infof("create nginx proxy config[%s/%s] success", rtn.Namespace, rtn.Name)
	return &rtn, nil
}

func createNginxDaemonSet(ctx context.Context, client kubernetes.Interface, config *v1.ConfigMap) error {
	logrus.Info("creating nginx proxy daemon set...")
	labels := map[string]string{
		"app": "apiserver-proxy",
	}
	daemonSet := appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "apiserver-proxy",
			Namespace: defaultNamespace,
			Labels:    labels,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: v1.PodSpec{
					HostNetwork: true,
					Volumes: []v1.Volume{
						{
							Name: "conf",
							VolumeSource: v1.VolumeSource{
								ConfigMap: &v1.ConfigMapVolumeSource{
									LocalObjectReference: v1.LocalObjectReference{
										Name: config.Name,
									},
								},
							},
						},
					},
					Containers: []v1.Container{
						{
							Name:  "apiserver-proxy",
							Image: "nginx",
							Ports: []v1.ContainerPort{
								{
									Name:          "nginx",
									Protocol:      v1.ProtocolTCP,
									ContainerPort: 3389,
									HostPort:      3389,
								},
							},
							VolumeMounts: []v1.VolumeMount{
								{
									Name:      "conf",
									MountPath: "/etc/nginx/nginx.conf",
									SubPath:   "nginx.conf",
								},
							},
						},
					},
				},
			},
		},
	}
	if _, err := client.AppsV1().DaemonSets(defaultNamespace).Create(ctx, &daemonSet, metav1.CreateOptions{}); err != nil {
		return err
	}
	logrus.Info("create nginx proxy daemon set success")
	return nil
}

func createProxyDaemonSets(ctx context.Context, cceClient *huawei_cce.CceClient, clusterInfo *model.ShowClusterResponse) (*[]model.Node, error) {
	k8sClient, err := cce.GetClusterClient(clusterInfo, cceClient)
	if err != nil {
		return nil, err
	}

	if err := createDefaultNamespace(ctx, k8sClient); err != nil {
		return nil, err
	}

	var config *v1.ConfigMap
	address := ""
	for _, endpoint := range *clusterInfo.Status.Endpoints {
		if *endpoint.Type == "Internal" {
			u, err := url.Parse(*endpoint.Url)
			if err != nil {
				return nil, err
			}
			address = u.Host
		}
	}
	if config, err = createNginxConfig(ctx, k8sClient, address); err != nil {
		return nil, err
	}

	if err := createNginxDaemonSet(ctx, k8sClient, config); err != nil {
		return nil, err
	}
	request := &model.ListNodesRequest{}
	request.ClusterId = *clusterInfo.Metadata.Uid

	nodes, err := cceClient.ListNodes(request)
	if err != nil {
		return nil, err
	}

	return nodes.Items, nil
}
