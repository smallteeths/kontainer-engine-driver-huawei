package cce

import (
	"errors"
	"fmt"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/utils"
	huawei_cce "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cce/v3"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cce/v3/model"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func GetClusterClient(cluster *model.ShowClusterResponse, cceClient *huawei_cce.CceClient) (kubernetes.Interface, error) {
	if cluster == nil || cceClient == nil {
		return nil, errors.New("cluster or cce client is nil")
	}
	request := &model.CreateKubernetesClusterCertRequest{}
	request.ClusterId = *cluster.Metadata.Uid
	request.Body = &model.CertDuration{
		Duration: int32(365),
	}
	kubeconfigResponse, err := cceClient.CreateKubernetesClusterCert(request)
	if err != nil {
		return nil, err
	}
	data, err := utils.Marshal(kubeconfigResponse)
	if err != nil {
		return nil, fmt.Errorf("error creating clientset: %v", err)
	}

	config, err := clientcmd.RESTConfigFromKubeConfig(data)
	if err != nil {
		logrus.Infof("Generate config Failed %+v", err)
		return nil, err
	}
	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error creating clientset: %v", err)
	}

	return clientSet, nil
}

func GetClusterCert(cluster *model.ShowClusterResponse, cceClient *huawei_cce.CceClient) (*model.CreateKubernetesClusterCertResponse, error) {
	if cluster == nil || cceClient == nil {
		return nil, errors.New("cluster or cce client is nil")
	}
	request := &model.CreateKubernetesClusterCertRequest{}
	request.ClusterId = *cluster.Metadata.Uid
	request.Body = &model.CertDuration{
		Duration: int32(365),
	}
	kubeconfigResponse, err := cceClient.CreateKubernetesClusterCert(request)
	if err != nil {
		return nil, err
	}
	return kubeconfigResponse, nil
}
