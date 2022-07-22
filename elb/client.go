package elb

import (
	"fmt"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	cce_model "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cce/v3/model"
	huawei_elb "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/elb/v3"
	elb_model "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/elb/v3/model"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/elb/v3/region"
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

func CreateELB(elbClient *huawei_elb.ElbClient, state *common.State) (*elb_model.CreateLoadBalancerResponse, error) {
	logrus.Info("creating ELB")

	request := &elb_model.CreateLoadBalancerRequest{}
	name := state.ClusterName + "-entrypoint"
	description := fmt.Sprintf("ELB for cce cluster %s api server", state.ClusterName)
	loadbalancerbody := &elb_model.CreateLoadBalancerOption{
		Name:        &name,
		Description: &description,
		VpcId:       &state.VipSubnetID,
	}
	request.Body = &elb_model.CreateLoadBalancerRequestBody{
		Loadbalancer: loadbalancerbody,
	}
	info, err := elbClient.CreateLoadBalancer(request)
	if err != nil {
		return nil, err
	}
	logrus.Info("create ELB success")
	state.APIServerELBID = info.Loadbalancer.Id
	return info, nil
}

func GetLoadBalancer(elbClient *huawei_elb.ElbClient, elbID string) (*elb_model.ShowLoadBalancerResponse, error) {
	request := &elb_model.ShowLoadBalancerRequest{}
	request.LoadbalancerId = elbID
	loadBalancerResponse, err := elbClient.ShowLoadBalancer(request)
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
	listenerbody := &elb_model.UpdateListenerOption{}
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

func CreateListener(elbClient *huawei_elb.ElbClient, state *common.State) (*elb_model.Listener, error) {
	logrus.Infof("creating listener for %s ...", state.APIServerELBID)
	name := state.ClusterName + "-apiserver"
	description := fmt.Sprintf("proxy cce cluster %s apiserver", state.ClusterName)
	request := &elb_model.CreateListenerRequest{
		Body: &elb_model.CreateListenerRequestBody{
			Listener: &elb_model.CreateListenerOption{
				LoadbalancerId: state.APIServerELBID,
				Protocol:       "TCP",
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
	LoadbalancerID := ""
	request := &elb_model.CreatePoolRequest{
		Body: &elb_model.CreatePoolRequestBody{
			Pool: &elb_model.CreatePoolOption{
				Protocol:       "TCP",
				LbAlgorithm:    "ROUND_ROBIN",
				ListenerId:     &listenerID,
				LoadbalancerId: &LoadbalancerID,
			},
		},
	}
	backendGroup, err := elbClient.CreatePool(request)
	if err != nil {
		return nil, err
	}
	state.PoolID = backendGroup.Pool.Id
	for _, backend := range *backends {
		memberRequest := &elb_model.CreateMemberRequest{
			Body: &elb_model.CreateMemberRequestBody{
				Member: &elb_model.CreateMemberOption{
					Address:      *backend.Status.PrivateIP,
					ProtocolPort: 3389,
					SubnetCidrId: &state.VipSubnetID,
				},
			},
		}
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

func DeleteHealthcheck(elbClient *huawei_elb.ElbClient, hlID string) (*elb_model.DeleteHealthMonitorResponse, error) {
	request := &elb_model.DeleteHealthMonitorRequest{}
	request.HealthmonitorId = hlID
	response, err := elbClient.DeleteHealthMonitor(request)
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

func DeleteLoadBalancer(elbClient *huawei_elb.ElbClient, loadBalancerID string) (*elb_model.DeleteLoadBalancerResponse, error) {
	request := &elb_model.DeleteLoadBalancerRequest{}
	request.LoadbalancerId = loadBalancerID
	response, err := elbClient.DeleteLoadBalancer(request)
	if err != nil {
		return nil, err
	}
	return response, nil
}
