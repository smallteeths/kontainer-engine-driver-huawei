package common

import (
	"context"
	"fmt"
	"strings"
	"time"

	huawei_cce "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cce/v3"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cce/v3/model"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	JobSuccess = "success"
	JobRunning = "running"
)

func WaitForJobReadyV3(ctx context.Context, cceClient *huawei_cce.CceClient, duration, timeout time.Duration, jobID string) (bool, *model.ShowJobResponse, error) {
	if jobID == "" {
		return false, nil, errors.New("job id is required")
	}
	var lastJobInfo *model.ShowJobResponse
	err := CustomWaitForCompleteUntilTrue(ctx, duration, timeout, func(ictx context.Context) (bool, error) {
		logrus.Infof("Querying job %s", jobID)
		request := &model.ShowJobRequest{}
		request.JobId = jobID
		response, err := cceClient.ShowJob(request)
		if err != nil {
			return false, err
		}
		switch strings.ToLower(*response.Status.Phase) {
		case JobSuccess:
			lastJobInfo = response
			return true, nil
		case JobRunning:
			logrus.Debugf("job %s is still running", jobID)
			return false, nil
		default:
			return false, fmt.Errorf("error for waiting %s job", jobID)
		}
	})
	return err == nil, lastJobInfo, err
}
