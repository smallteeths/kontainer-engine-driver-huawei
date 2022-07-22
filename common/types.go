package common

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/rancher/rancher/pkg/kontainer-engine/types"
	"net/http"
	"time"
)

const (
	DefaultCidr     = "192.168.0.0/24"
	DefaultGateway  = "192.168.0.1"
	DefaultTimeout  = 30 * time.Second
	DefaultDuration = 5 * time.Second
)

type ClientInterface interface {
	GetAPIHostname() string
	GetAPIEndpoint() string
	GetBaseURL(endpoint, prefix string) string
	DoRequest(ctx context.Context, serviceType, method, url string, input interface{}) (*http.Response, error)
}

type State struct {
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
	NodeConfig            *NodeConfig
	AuthMode              string
	APIServerELBID        string
	PoolID                string

	ClusterInfo types.ClusterInfo
}

//ErrorInfo Error message
type ErrorInfo struct {
	StatusCode  int             `json:"-"`
	Code        string          `json:"code"`
	Description string          `json:"message"`
	ErrorV1     json.RawMessage `json:"error,omitempty"`
}

type ErrorInfoV1 struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

type OddErrorInfo struct {
	ErrorCode      string `json:"error_code,omitempty"`
	ErrorMassage   string `json:"error_msg,omitempty"`
	ErrorCodeInner string `json:"errorCode,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

func (err *ErrorInfo) UnmarshalJSON(b []byte) error {
	errInfo := struct {
		StatusCode  int             `json:"-"`
		Code        string          `json:"code"`
		Description string          `json:"message"`
		ErrorV1     json.RawMessage `json:"error,omitempty"`
	}{}
	if err := json.Unmarshal(b, &errInfo); err != nil {
		return err
	}
	*err = errInfo
	if errInfo.Code != "" || errInfo.Description != "" {
		return nil
	}
	if len(errInfo.ErrorV1) != 0 {
		errv1 := ErrorInfoV1{}
		if err := json.Unmarshal(errInfo.ErrorV1, &errv1); err != nil {
			return err
		}
		err.Code = errv1.Code
		err.Description = errv1.Message
		err.ErrorV1 = nil
		return nil
	}
	oddErrorInfo := OddErrorInfo{}
	if err := json.Unmarshal(b, &oddErrorInfo); err != nil {
		return err
	}
	err.Code = oddErrorInfo.ErrorCode
	err.Description = oddErrorInfo.ErrorMassage
	return nil
}

func (err *ErrorInfo) Error() string {
	return fmt.Sprintf("http status code[%d], huawei cloud api error code[%s], message: [%s]", err.StatusCode, err.Code, err.Description)
}

type NodeConfig struct {
	NodeFlavor          string
	AvailableZone       string
	SSHName             string
	RootVolumeSize      int64
	RootVolumeType      string
	DataVolumeSize      int64
	DataVolumeType      string
	BillingMode         int64
	NodeCount           int64
	NodeOperationSystem string
	PublicIP            PublicIP
	ExtendParam         ExtendParam
	UserPassword        UserPassword
	NodeLabels          map[string]string
}

type UserPassword struct {
	UserName string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type Bandwidth struct {
	ChargeMode string `json:"chargemode,omitempty"`
	Size       int64  `json:"size,omitempty"`
	ShareType  string `json:"sharetype,omitempty"`
}

type Eip struct {
	Iptype    string    `json:"iptype,omitempty"`
	Bandwidth Bandwidth `json:"bandwidth,omitempty"`
}

type PublicIP struct {
	Ids   []string `json:"ids,omitempty"`
	Count int64    `json:"count,omitempty"`
	Eip   *Eip     `json:"eip,omitempty"`
}

type ExtendParam struct {
	BMSPeriodType  string `json:"periodType,omitempty"`
	BMSPeriodNum   int64  `json:"periodNum,omitempty"`
	BMSIsAutoRenew string `json:"isAutoRenew,omitempty"`
}

func (state *State) Validate() error {
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
