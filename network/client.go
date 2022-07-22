package network

import (
	"context"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	eip_v2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/eip/v2"
	eip_model_v2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/eip/v2/model"
	eip "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/eip/v3"
	eip_model "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/eip/v3/model"
	vpc "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2"
	vpc_model "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2/model"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2/region"
	"github.com/pkg/errors"
	"github.com/rancher/kontainer-engine-driver-huawei/common"
	"github.com/sirupsen/logrus"
)

func NewNetWorkClient(baseClient *common.Client) *vpc.VpcClient {
	auth := basic.NewCredentialsBuilder().
		WithAk(baseClient.AccessKey).
		WithSk(baseClient.SecretKey).
		WithProjectId(baseClient.ProjectID).
		Build()

	client := vpc.NewVpcClient(
		vpc.VpcClientBuilder().
			WithRegion(region.ValueOf(baseClient.Region)).
			WithCredential(auth).
			Build())

	return client
}

func NewEipClient(baseClient *common.Client) *eip.EipClient {
	auth := basic.NewCredentialsBuilder().
		WithAk(baseClient.AccessKey).
		WithSk(baseClient.SecretKey).
		WithProjectId(baseClient.ProjectID).
		Build()

	client := eip.NewEipClient(
		eip.EipClientBuilder().
			WithRegion(region.ValueOf(baseClient.Region)).
			WithCredential(auth).
			Build())

	return client
}

func NewEipV2Client(baseClient *common.Client) *eip_v2.EipClient {
	auth := basic.NewCredentialsBuilder().
		WithAk(baseClient.AccessKey).
		WithSk(baseClient.SecretKey).
		WithProjectId(baseClient.ProjectID).
		Build()

	client := eip_v2.NewEipClient(
		eip_v2.EipClientBuilder().
			WithRegion(region.ValueOf(baseClient.Region)).
			WithCredential(auth).
			Build())

	return client
}

func ShowPublicip(client *eip.EipClient, publicipID string) (*eip_model.ShowPublicipResponse, error) {
	request := &eip_model.ShowPublicipRequest{}
	request.PublicipId = publicipID
	response, err := client.ShowPublicip(request)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func UpdatePublicip(client *eip_v2.EipClient, publicipID string) (*eip_model_v2.UpdatePublicipResponse, error) {
	request := &eip_model_v2.UpdatePublicipRequest{}
	publicipbody := &eip_model_v2.UpdatePublicipOption{}
	request.PublicipId = publicipID
	request.Body = &eip_model_v2.UpdatePublicipsRequestBody{
		Publicip: publicipbody,
	}
	response, err := client.UpdatePublicip(request)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func CreateVPC(ctx context.Context, networkClient *vpc.VpcClient, state *common.State) (*vpc_model.ShowVpcResponse, error) {
	logrus.Info("setting up vpc...")
	name := state.ClusterName + "-vpc"
	cidr := "192.168.0.0/24"
	vpcReq := &vpc_model.CreateVpcRequest{
		Body: &vpc_model.CreateVpcRequestBody{
			Vpc: &vpc_model.CreateVpcOption{
				Name: &name,
				Cidr: &cidr,
			},
		},
	}
	rtn, err := networkClient.CreateVpc(vpcReq)
	if err != nil {
		return nil, errors.Wrap(err, "error creating vpc")
	}
	state.VpcID = rtn.Vpc.Id
	reqGetVpc := &vpc_model.ShowVpcRequest{}
	reqGetVpc.VpcId = state.VpcID
	if err = common.WaitForCompleteWithError(ctx, func(ictx context.Context) error {
		_, err := networkClient.ShowVpc(reqGetVpc)
		return err
	}); err != nil {
		return nil, err
	}
	logrus.Infof("bring up vpc %s success", state.VpcID)
	return networkClient.ShowVpc(reqGetVpc)
}

func CreateSubnet(ctx context.Context, networkClient *vpc.VpcClient, state *common.State) (*vpc_model.ShowSubnetResponse, error) {
	logrus.Info("setting up subnet...")
	primaryDNS := "114.114.114.114"
	secondaryDNS := "8.8.8.8"
	dhcpEnable := true
	subnetReq := &vpc_model.CreateSubnetRequest{
		Body: &vpc_model.CreateSubnetRequestBody{
			Subnet: &vpc_model.CreateSubnetOption{
				Name:         state.ClusterName + "-subnet",
				Cidr:         common.DefaultCidr,
				GatewayIp:    common.DefaultGateway,
				VpcId:        state.VpcID,
				PrimaryDns:   &primaryDNS,
				SecondaryDns: &secondaryDNS,
				DhcpEnable:   &dhcpEnable,
			},
		},
	}
	rtn, err := networkClient.CreateSubnet(subnetReq)
	if err != nil {
		return nil, errors.Wrap(err, "error creating subnet")
	}
	state.SubnetID = rtn.Subnet.Id
	getSubnetrequest := &vpc_model.ShowSubnetRequest{}
	getSubnetrequest.SubnetId = state.SubnetID
	if err = common.WaitForCompleteWithError(ctx, func(ictx context.Context) error {
		_, err := networkClient.ShowSubnet(getSubnetrequest)
		return err
	}); err != nil {
		return nil, err
	}
	logrus.Infof("set up subnet %s success", state.SubnetID)
	return networkClient.ShowSubnet(getSubnetrequest)
}

func DeleteVPC(networkClient *vpc.VpcClient, vpcID string) (*vpc_model.DeleteVpcResponse, error) {
	request := &vpc_model.DeleteVpcRequest{}
	request.VpcId = vpcID
	response, err := networkClient.DeleteVpc(request)
	if err == nil {
		return nil, err
	}
	return response, nil
}

func DeleteSubnet(networkClient *vpc.VpcClient, vpcID string, subnetID string) (*vpc_model.DeleteSubnetResponse, error) {
	request := &vpc_model.DeleteSubnetRequest{}
	request.VpcId = vpcID
	request.VpcId = vpcID
	request.SubnetId = subnetID
	response, err := networkClient.DeleteSubnet(request)
	if err == nil {
		return nil, err
	}
	return response, nil
}
