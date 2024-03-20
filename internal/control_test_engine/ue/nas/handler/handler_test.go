package handler

import (
	"fmt"
	"my5G-RANTester/config"
	"my5G-RANTester/internal/control_test_engine/ue/context"
	"testing"

	"github.com/BENHSU0723/nas/uePolicyContainer"
)

func Test_HandleMsgTypeManageUEPolicyCommand(t *testing.T) {
	var ue context.UEContext
	conf := config.Load("/home/ben/ben_github/PacketRusher/config/config.yml")
	// new UE context
	ue.NewRanUeContext(
		conf.Ue.Msin,
		conf.GetUESecurityCapability(),
		conf.Ue.Key,
		conf.Ue.Opc,
		"c9e8763286b5b9ffbdf56e1297d0887b",
		conf.Ue.Amf,
		conf.Ue.Sqn,
		conf.Ue.Hplmn.Mcc,
		conf.Ue.Hplmn.Mnc,
		conf.Ue.RoutingIndicator,
		conf.Ue.Dnn,
		int32(conf.Ue.Snssai.Sst),
		conf.Ue.Snssai.Sd,
		conf.Ue.TunnelMode,
		nil,
		nil,
		1)

	// 0 70 8 242 147 0 65 0 1 0 61 1 33 0 9 16 10 60 1 0 255 255 255 0 21 20 0 18 2 6 0 1 1 1 2 3 4 8 105 110 116 101 114 110 101 116 25 255 1 1 21 20 0 18 2 6 0 1 1 1 2 3 4 8 73 110 116 101 114 110 101 116
	// 0,70,8,242,147,0,65,0,1,0,61,1,33,0,9,16,10,60,1,0,255,255,255,0,21,20,0,18,2,6,0,1,1,1,2,3,4,8,105,110,116,101,114,110,101,116,25,255,1,1,21,20,0,18,2,6,0,1,1,1,2,3,4,8,73,110,116,101,114,110,101,116

	listContent := []byte{0, 70, 8, 242, 147, 0, 65, 0, 1, 0, 61, 1, 33, 0, 9, 16, 10, 60, 1, 0, 255, 255, 255, 0, 21, 20, 0, 18, 2, 6, 0, 1, 1, 1, 2, 3, 4, 8, 105, 110, 116, 101, 114, 110, 101, 116, 25, 255, 1, 1, 21, 20, 0, 18, 2, 6, 0, 1, 1, 1, 2, 3, 4, 8, 73, 110, 116, 101, 114, 110, 101, 116}
	var uePolContainer uePolicyContainer.UePolicyContainer
	uePolContainer.ManageUEPolicyCommand = uePolicyContainer.NewManageUEPolicyCommand(0x00)
	uePolContainer.ManageUEPolicyCommand.SetUEPolicySectionManagementListContent(listContent)
	err := HandleMsgTypeManageUEPolicyCommand(uePolContainer, &ue)
	if err != nil {
		fmt.Printf("Error test of HandleMsgTypeManageUEPolicyCommand:%+v\n", err)
		t.Errorf("Error test of HandleMsgTypeManageUEPolicyCommand:%+v\n", err)
	} else {
		t.Log("Pass HandleMsgTypeManageUEPolicyCommand")
	}
}
