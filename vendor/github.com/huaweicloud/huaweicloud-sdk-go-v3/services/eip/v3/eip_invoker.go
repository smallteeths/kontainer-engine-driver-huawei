package v3

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/invoker"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/eip/v3/model"
)

type ListCommonPoolsInvoker struct {
	*invoker.BaseInvoker
}

func (i *ListCommonPoolsInvoker) Invoke() (*model.ListCommonPoolsResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ListCommonPoolsResponse), nil
	}
}

type ListPublicBorderGroupsInvoker struct {
	*invoker.BaseInvoker
}

func (i *ListPublicBorderGroupsInvoker) Invoke() (*model.ListPublicBorderGroupsResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ListPublicBorderGroupsResponse), nil
	}
}

type ListShareBandwidthTypesInvoker struct {
	*invoker.BaseInvoker
}

func (i *ListShareBandwidthTypesInvoker) Invoke() (*model.ListShareBandwidthTypesResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ListShareBandwidthTypesResponse), nil
	}
}

type AssociatePublicipsInvoker struct {
	*invoker.BaseInvoker
}

func (i *AssociatePublicipsInvoker) Invoke() (*model.AssociatePublicipsResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.AssociatePublicipsResponse), nil
	}
}

type DisassociatePublicipsInvoker struct {
	*invoker.BaseInvoker
}

func (i *DisassociatePublicipsInvoker) Invoke() (*model.DisassociatePublicipsResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.DisassociatePublicipsResponse), nil
	}
}

type ListPublicipPoolInvoker struct {
	*invoker.BaseInvoker
}

func (i *ListPublicipPoolInvoker) Invoke() (*model.ListPublicipPoolResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ListPublicipPoolResponse), nil
	}
}

type ListPublicipsInvoker struct {
	*invoker.BaseInvoker
}

func (i *ListPublicipsInvoker) Invoke() (*model.ListPublicipsResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ListPublicipsResponse), nil
	}
}

type ShowPublicipInvoker struct {
	*invoker.BaseInvoker
}

func (i *ShowPublicipInvoker) Invoke() (*model.ShowPublicipResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ShowPublicipResponse), nil
	}
}

type ShowPublicipPoolInvoker struct {
	*invoker.BaseInvoker
}

func (i *ShowPublicipPoolInvoker) Invoke() (*model.ShowPublicipPoolResponse, error) {
	if result, err := i.BaseInvoker.Invoke(); err != nil {
		return nil, err
	} else {
		return result.(*model.ShowPublicipPoolResponse), nil
	}
}
