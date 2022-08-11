package cce

import (
	"context"
	"time"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	huawei_cce "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cce/v3"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cce/v3/model"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cce/v3/region"
	"github.com/pkg/errors"
	"github.com/rancher/kontainer-engine-driver-huawei/common"
	"github.com/sirupsen/logrus"
)

func GetCCEServiceClient(baseClient *common.Client) *huawei_cce.CceClient {
	auth := basic.NewCredentialsBuilder().
		WithAk(baseClient.AccessKey).
		WithSk(baseClient.SecretKey).
		WithProjectId(baseClient.ProjectID).
		Build()

	client := huawei_cce.NewCceClient(
		huawei_cce.CceClientBuilder().
			WithRegion(region.ValueOf(baseClient.Region)).
			WithCredential(auth).
			Build())

	return client
}

func CreateCluster(ctx context.Context, cceClient *huawei_cce.CceClient, state *common.State) (*model.ShowClusterResponse, error) {
	logrus.Info("creating cluster...")
	clusterReq := common.GetClusterRequestFromState(*state)
	rtn, err := cceClient.CreateCluster(clusterReq)
	if err != nil {
		return nil, errors.Wrap(err, "error creating cluster")
	}
	state.ClusterID = *rtn.Metadata.Uid
	state.ClusterJobID = *rtn.Status.JobID
	ok, _, err := common.WaitForJobReadyV3(ctx, cceClient, 20*time.Second, 30*time.Minute, state.ClusterJobID)
	if !ok {
		return nil, errors.Wrapf(err, "error waiting for cluster job %s", state.ClusterJobID)
	}
	request := &model.ShowClusterRequest{}
	request.ClusterId = state.ClusterID
	logrus.Infof("cluster provisioned successfully")
	return cceClient.ShowCluster(request)
}

func ShowCluster(cceClient *huawei_cce.CceClient, clusterID string) (*model.ShowClusterResponse, error) {
	request := &model.ShowClusterRequest{}
	request.ClusterId = clusterID
	response, err := cceClient.ShowCluster(request)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func DeleteCluster(cceClient *huawei_cce.CceClient, clusterID string) (*model.DeleteClusterResponse, error) {
	request := &model.DeleteClusterRequest{}
	deleteEfsRequest := model.GetDeleteClusterRequestDeleteEfsEnum().TRY
	request.DeleteEfs = &deleteEfsRequest
	deleteEvsRequest := model.GetDeleteClusterRequestDeleteEvsEnum().TRY
	request.DeleteEvs = &deleteEvsRequest
	deleteNetRequest := model.GetDeleteClusterRequestDeleteNetEnum().TRY
	request.DeleteNet = &deleteNetRequest
	deleteObsRequest := model.GetDeleteClusterRequestDeleteObsEnum().TRY
	request.DeleteObs = &deleteObsRequest
	deleteSfsRequest := model.GetDeleteClusterRequestDeleteSfsEnum().TRY
	request.DeleteSfs = &deleteSfsRequest
	request.ClusterId = clusterID
	deleteClusterResponse, err := cceClient.DeleteCluster(request)
	if err != nil {
		return nil, err
	}
	return deleteClusterResponse, nil
}

func CreateNodes(ctx context.Context, clusterID string, cceClient *huawei_cce.CceClient, state *common.State, count int32) (*model.CreateNodeResponse, error) {
	logrus.Infof("creating worker nodes...")
	nodeReq := getNodeRequirement(*state, count, clusterID)
	nodeResponse, err := cceClient.CreateNode(nodeReq)
	if err != nil {
		logrus.WithError(err).Warnf("trying to create node for cluster %s again", state.ClusterID)
		_, err = cceClient.CreateNode(nodeReq)
		//retry fail
		if err != nil {
			return nil, errors.Wrap(err, "error when creating node(s) for cluster")
		}
	}
	ok, _, err := common.WaitForJobReadyV3(ctx, cceClient, 20*time.Second, 30*time.Minute, *nodeResponse.Status.JobID)
	if !ok {
		return nil, errors.Wrapf(err, "error waiting for node job %s", state.ClusterJobID)
	}
	logrus.Info("creating worker nodes complete")
	return nodeResponse, nil
}

func DeleteNodes(ctx context.Context, clusterID string, cceClient *huawei_cce.CceClient, nodeList []model.Node) error {
	logrus.Infof("deleteing worker nodes...")
	for _, node := range nodeList {
		request := &model.DeleteNodeRequest{}
		request.ClusterId = clusterID
		request.NodeId = *node.Metadata.Uid
		logrus.Infof("deleteing nodes... %s", request.NodeId)
		response, err := cceClient.DeleteNode(request)
		if err != nil {
			return err
		}
		ok, _, err := common.WaitForJobReadyV3(ctx, cceClient, 20*time.Second, 30*time.Minute, *response.Status.JobID)
		if !ok {
			return errors.Wrapf(err, "error waiting for delete node %s", request.NodeId)
		}
	}
	return nil
}

func getNodeRequirement(state common.State, count int32, clusterID string) *model.CreateNodeRequest {
	billingModeSpec := int32(state.ClusterBillingMode)
	nodeconf := &model.NodeCreateRequest{
		Kind:       "Node",
		ApiVersion: "v3",
		Metadata: &model.NodeMetadata{
			Name:   &state.DisplayName,
			Labels: state.NodeConfig.NodeLabels,
		},
		Spec: &model.NodeSpec{
			Flavor: state.NodeConfig.NodeFlavor,
			Az:     state.NodeConfig.AvailableZone,
			Login: &model.Login{
				SshKey: &state.NodeConfig.SSHName,
				UserPassword: &model.UserPassword{
					Username: &state.NodeConfig.UserPassword.UserName,
					Password: state.NodeConfig.UserPassword.Password,
				},
			},
			RootVolume: &model.Volume{
				Size:       int32(state.NodeConfig.RootVolumeSize),
				Volumetype: state.NodeConfig.RootVolumeType,
			},
			DataVolumes: []model.Volume{
				{
					Size:       int32(state.NodeConfig.DataVolumeSize),
					Volumetype: state.NodeConfig.DataVolumeType,
				},
			},
			PublicIP:    &model.NodePublicIp{},
			Count:       &count,
			BillingMode: &billingModeSpec,
			ExtendParam: nil,
		},
	}
	periodNum := int32(state.NodeConfig.ExtendParam.BMSPeriodNum)
	extendParam := &model.NodeExtendParam{
		PeriodType:  &state.NodeConfig.ExtendParam.BMSPeriodType,
		PeriodNum:   &periodNum,
		IsAutoRenew: &state.NodeConfig.ExtendParam.BMSIsAutoRenew,
	}

	if state.NodeConfig.ExtendParam.BMSPeriodType != "" &&
		state.NodeConfig.ExtendParam.BMSPeriodNum != 0 &&
		state.NodeConfig.ExtendParam.BMSIsAutoRenew != "" {
		nodeconf.Spec.ExtendParam = extendParam
	}

	if len(state.NodeConfig.PublicIP.Ids) > 0 {
		nodeconf.Spec.PublicIP.Ids = &state.NodeConfig.PublicIP.Ids
	}
	chargeMode := "traffic"
	if state.NodeConfig.PublicIP.Eip.Bandwidth.ChargeMode != "traffic" {
		chargeMode = ""
	}
	if state.NodeConfig.PublicIP.Count > 0 {
		publicIPCount := int32(state.NodeConfig.PublicIP.Count)
		eipBandwidthSize := int32(state.NodeConfig.PublicIP.Eip.Bandwidth.Size)
		nodeconf.Spec.PublicIP.Count = &publicIPCount
		nodeconf.Spec.PublicIP.Eip = &model.NodeEipSpec{
			Iptype: &state.NodeConfig.PublicIP.Eip.Iptype,
			Bandwidth: &model.NodeBandwidth{
				Chargemode: &chargeMode,
				Size:       &eipBandwidthSize,
				Sharetype:  &state.NodeConfig.PublicIP.Eip.Bandwidth.ShareType,
			},
		}
	}
	request := &model.CreateNodeRequest{}
	request.ClusterId = clusterID
	request.Body = nodeconf
	return request
}
