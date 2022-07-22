package common

import (
	"context"
	"time"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cce/v3/model"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type Client struct {
	AccessKey string
	SecretKey string
	ProjectID string
	Region    string
}

func NewClient(ak, sk, region, projectID string) *Client {
	client := &Client{
		AccessKey: ak,
		SecretKey: sk,
		Region:    region,
		ProjectID: projectID,
	}
	return client
}

func GetClusterRequestFromState(state State) *model.CreateClusterRequest {
	var containerNetWorkMode model.ContainerNetworkMode
	switch state.ContainerNetworkMode {
	case "overlay_l2":
		containerNetWorkMode = model.GetContainerNetworkModeEnum().OVERLAY_L2
	case "vpc-router":
		containerNetWorkMode = model.GetContainerNetworkModeEnum().VPC_ROUTER
	default:
		containerNetWorkMode = model.GetContainerNetworkModeEnum().ENI
	}
	var clusterSpecType model.ClusterSpecType
	switch state.ClusterType {
	case "ARM64":
		clusterSpecType = model.GetClusterSpecTypeEnum().ARM64
	default:
		clusterSpecType = model.GetClusterSpecTypeEnum().VIRTUAL_MACHINE
	}
	billingModeSpec := int32(state.ClusterBillingMode)

	clusterReq := &model.Cluster{
		Kind:       "cluster",
		ApiVersion: "v3",
		Metadata: &model.ClusterMetadata{
			Name:   state.DisplayName,
			Labels: state.ClusterLabels,
		},
		Spec: &model.ClusterSpec{
			Type:    &clusterSpecType,
			Flavor:  state.ClusterFlavor,
			Version: &state.ClusterVersion,
			HostNetwork: &model.HostNetwork{
				Vpc:    state.VpcID,
				Subnet: state.SubnetID,
			},
			ContainerNetwork: &model.ContainerNetwork{
				Mode: containerNetWorkMode,
				Cidr: &state.ContainerNetworkCidr,
			},
			BillingMode: &billingModeSpec,
			Authentication: &model.Authentication{
				Mode: &state.AuthMode,
			},
		},
	}
	if state.AuthMode == "authenticating_proxy" {
		clusterReq.Spec.Authentication.AuthenticatingProxy.Ca = &state.AuthenticatingProxyCa
	}
	request := &model.CreateClusterRequest{}
	request.Body = clusterReq

	return request
}

func CustomWaitForCompleteUntilTrue(ctx context.Context, duration time.Duration, timeout time.Duration, conditionFunc func(context.Context) (bool, error)) error {
	return waitForCompleteUntilTrue(ctx, duration, timeout, conditionFunc)
}

func WaitForCompleteWithError(ctx context.Context, conditionFunc func(context.Context) error) error {
	t := time.NewTicker(DefaultDuration)
	defer t.Stop()
	timoutCtx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()
	var lastErr error
	for {
		select {
		case <-t.C:
			err := conditionFunc(timoutCtx)
			lastErr = err
			if err == nil {
				return nil
			}
		case <-timoutCtx.Done():
			return errors.Wrap(lastErr, "time out waiting delete with last error")
		}
	}
}

func waitForCompleteUntilTrue(ctx context.Context, duration time.Duration, timeout time.Duration, conditionFunc func(context.Context) (bool, error)) error {
	t := time.NewTicker(duration)
	defer t.Stop()
	timoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		select {
		case <-t.C:
			logrus.Debug("wait function ticking")
			ok, err := conditionFunc(timoutCtx)
			if err != nil {
				logrus.Debugf("wait function gets error: %s", err.Error())
				return err
			}
			if ok {
				return nil
			}
		case <-timoutCtx.Done():
			return errors.New("time out waiting condition with last error")
		}
	}
}
