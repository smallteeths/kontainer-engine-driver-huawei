package elb

import (
	"fmt"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	cce_model "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cce/v3/model"
	huawei_elb "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/elb/v2"
	elb_model "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/elb/v2/model"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/elb/v2/region"
	"github.com/rancher/kontainer-engine-driver-huawei/common"
	"github.com/sirupsen/logrus"
)

func NewElbClient(baseClient *common.Client) *huawei_elb.ElbClient {
	auth := basic.NewCredentialsBuilder().
		WithAk(baseClient.AccessKey).
		WithSk(baseClient.SecretKey).
		WithProjectId(baseClient.ProjectID).
		Build()

	client := huawei_elb.NewElbClient(
		huawei_elb.ElbClientBuilder().
			WithRegion(region.ValueOf(baseClient.Region)).
			WithCredential(auth).
			Build())

	return client
}

func CreateELB(elbClient *huawei_elb.ElbClient, state *common.State) (*elb_model.CreateLoadbalancerResponse, error) {
	logrus.Info("creating ELB")
	request := &elb_model.CreateLoadbalancerRequest{}
	name := state.ClusterName + "-entrypoint"
	description := fmt.Sprintf("ELB for cce cluster %s api server", state.ClusterName)
	loadbalancerbody := &elb_model.CreateLoadbalancerReq{
		Name:        &name,
		Description: &description,
		VipSubnetId: state.VipSubnetID,
	}
	request.Body = &elb_model.CreateLoadbalancerRequestBody{
		Loadbalancer: loadbalancerbody,
	}
	info, err := elbClient.CreateLoadbalancer(request)
	if err != nil {
		return nil, err
	}
	logrus.Info("create ELB success")
	state.APIServerELBID = info.Loadbalancer.Id
	return info, nil
}

func GetLoadBalancer(elbClient *huawei_elb.ElbClient, elbID string) (*elb_model.ShowLoadbalancerResponse, error) {
	request := &elb_model.ShowLoadbalancerRequest{}
	request.LoadbalancerId = elbID
	loadBalancerResponse, err := elbClient.ShowLoadbalancer(request)
	if err != nil {
		return nil, err
	}
	return loadBalancerResponse, nil
}

func ListListeners(elbClient *huawei_elb.ElbClient) (*elb_model.ListListenersResponse, error) {
	request := &elb_model.ListListenersRequest{}
	limitRequest := int32(1000)
	request.Limit = &limitRequest
	listeners, err := elbClient.ListListeners(request)
	if err != nil {
		return nil, err
	}
	return listeners, nil
}

func UpdateListener(elbClient *huawei_elb.ElbClient, listenerID string) (*elb_model.UpdateListenerResponse, error) {
	request := &elb_model.UpdateListenerRequest{}
	request.ListenerId = listenerID
	listenerbody := &elb_model.UpdateListenerReq{}
	request.Body = &elb_model.UpdateListenerRequestBody{
		Listener: listenerbody,
	}
	response, err := elbClient.UpdateListener(request)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func DeleteListener(elbClient *huawei_elb.ElbClient, listenerID string) (*elb_model.DeleteListenerResponse, error) {
	request := &elb_model.DeleteListenerRequest{}
	request.ListenerId = listenerID
	response, err := elbClient.DeleteListener(request)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func CreateListener(elbClient *huawei_elb.ElbClient, state *common.State) (*elb_model.ListenerResp, error) {
	logrus.Infof("creating listener for %s ...", state.APIServerELBID)
	name := state.ClusterName + "-apiserver"
	description := fmt.Sprintf("proxy cce cluster %s apiserver", state.ClusterName)
	request := &elb_model.CreateListenerRequest{
		Body: &elb_model.CreateListenerRequestBody{
			Listener: &elb_model.CreateListenerReq{
				LoadbalancerId: state.APIServerELBID,
				Protocol:       elb_model.GetCreateListenerReqProtocolEnum().TCP,
				ProtocolPort:   5443,
				Name:           &name,
				Description:    &description,
			},
		},
	}
	resp, err := elbClient.CreateListener(request)
	if err != nil {
		return nil, err
	}
	logrus.Info("create listener success")
	return resp.Listener, nil
}

func AddBackends(listenerID string, elbClient *huawei_elb.ElbClient, backends *[]cce_model.Node, state *common.State) (*elb_model.CreatePoolResponse, error) {
	logrus.Infof("creating backends for listener %s", listenerID)
	request := &elb_model.CreatePoolRequest{
		Body: &elb_model.CreatePoolRequestBody{
			Pool: &elb_model.CreatePoolReq{
				Protocol:       elb_model.GetCreatePoolReqProtocolEnum().TCP,
				LbAlgorithm:    "ROUND_ROBIN",
				ListenerId:     &listenerID,
				LoadbalancerId: &state.APIServerELBID,
			},
		},
	}
	backendGroup, err := elbClient.CreatePool(request)
	if err != nil {
		return nil, err
	}
	logrus.Infof("creating backends success LoadbalancerId: %s", state.APIServerELBID)
	state.PoolID = backendGroup.Pool.Id
	for _, backend := range *backends {
		memberRequest := &elb_model.CreateMemberRequest{
			Body: &elb_model.CreateMemberRequestBody{
				Member: &elb_model.CreateMemberReq{
					Address:      *backend.Status.PrivateIP,
					ProtocolPort: 3389,
					SubnetId:     state.VipSubnetID,
				},
			},
		}
		memberRequest.PoolId = state.PoolID
		if _, err = elbClient.CreateMember(memberRequest); err != nil {
			return nil, err
		}
	}
	logrus.Info("create backend success")
	return backendGroup, err
}

func ShowPool(elbClient *huawei_elb.ElbClient, poolID string) (*elb_model.ShowPoolResponse, error) {
	request := &elb_model.ShowPoolRequest{}
	request.PoolId = poolID
	response, err := elbClient.ShowPool(request)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func DeleteHealthcheck(elbClient *huawei_elb.ElbClient, hlID string) (*elb_model.DeleteHealthmonitorResponse, error) {
	request := &elb_model.DeleteHealthmonitorRequest{}
	request.HealthmonitorId = hlID
	response, err := elbClient.DeleteHealthmonitor(request)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func DeleteMember(elbClient *huawei_elb.ElbClient, poolID string, memberID string) (*elb_model.DeleteMemberResponse, error) {
	request := &elb_model.DeleteMemberRequest{}
	request.PoolId = poolID
	request.MemberId = memberID
	response, err := elbClient.DeleteMember(request)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func DeletePool(elbClient *huawei_elb.ElbClient, poolID string) (*elb_model.DeletePoolResponse, error) {
	request := &elb_model.DeletePoolRequest{}
	request.PoolId = poolID
	response, err := elbClient.DeletePool(request)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func DeleteLoadBalancer(elbClient *huawei_elb.ElbClient, loadBalancerID string) (*elb_model.DeleteLoadbalancerResponse, error) {
	request := &elb_model.DeleteLoadbalancerRequest{}
	request.LoadbalancerId = loadBalancerID
	response, err := elbClient.DeleteLoadbalancer(request)
	if err != nil {
		return nil, err
	}
	return response, nil
}
