/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package handler

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"my5G-RANTester/internal/control_test_engine/ue/context"
	"my5G-RANTester/internal/control_test_engine/ue/nas/message/nas_control"
	"my5G-RANTester/internal/control_test_engine/ue/nas/message/nas_control/mm_5gs"
	"my5G-RANTester/internal/control_test_engine/ue/nas/message/sender"
	"my5G-RANTester/internal/control_test_engine/ue/nas/trigger"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BENHSU0723/nas"
	"github.com/BENHSU0723/nas/nasMessage"
	"github.com/BENHSU0723/nas/uePolicyContainer"
	"github.com/BENHSU0723/openapi/models"
	log "github.com/sirupsen/logrus"
)

func HandlerAuthenticationReject(ue *context.UEContext, message *nas.Message) {

	log.Info("[UE][NAS] Authentication of UE ", ue.GetUeId(), " failed")

	ue.SetStateMM_DEREGISTERED()
}

func HandlerAuthenticationRequest(ue *context.UEContext, message *nas.Message) {
	var authenticationResponse []byte

	// check the mandatory fields
	if reflect.ValueOf(message.AuthenticationRequest.ExtendedProtocolDiscriminator).IsZero() {
		log.Fatal("[UE][NAS] Error in Authentication Request, Extended Protocol is missing")
	}

	if message.AuthenticationRequest.ExtendedProtocolDiscriminator.GetExtendedProtocolDiscriminator() != 126 {
		log.Fatal("[UE][NAS] Error in Authentication Request, Extended Protocol not the expected value")
	}

	if message.AuthenticationRequest.SpareHalfOctetAndSecurityHeaderType.GetSpareHalfOctet() != 0 {
		log.Fatal("[UE][NAS] Error in Authentication Request, Spare Half Octet not the expected value")
	}

	if message.AuthenticationRequest.SpareHalfOctetAndSecurityHeaderType.GetSecurityHeaderType() != 0 {
		log.Fatal("[UE][NAS] Error in Authentication Request, Security Header Type not the expected value")
	}

	if reflect.ValueOf(message.AuthenticationRequest.AuthenticationRequestMessageIdentity).IsZero() {
		log.Fatal("[UE][NAS] Error in Authentication Request, Message Type is missing")
	}

	if message.AuthenticationRequest.AuthenticationRequestMessageIdentity.GetMessageType() != 86 {
		log.Fatal("[UE][NAS] Error in Authentication Request, Message Type not the expected value")
	}

	if message.AuthenticationRequest.SpareHalfOctetAndNgksi.GetSpareHalfOctet() != 0 {
		log.Fatal("[UE][NAS] Error in Authentication Request, Spare Half Octet not the expected value")
	}

	if message.AuthenticationRequest.SpareHalfOctetAndNgksi.GetNasKeySetIdentifiler() == 7 {
		log.Fatal("[UE][NAS] Error in Authentication Request, ngKSI not the expected value")
	}

	if reflect.ValueOf(message.AuthenticationRequest.ABBA).IsZero() {
		log.Fatal("[UE][NAS] Error in Authentication Request, ABBA is missing")
	}

	if message.AuthenticationRequest.GetABBAContents() == nil {
		log.Fatal("[UE][NAS] Error in Authentication Request, ABBA Content is missing")
	}

	// getting RAND and AUTN from the message.
	rand := message.AuthenticationRequest.GetRANDValue()
	autn := message.AuthenticationRequest.GetAUTN()

	// getting resStar
	paramAutn, check := ue.DeriveRESstarAndSetKey(ue.UeSecurity.AuthenticationSubs, rand[:], ue.UeSecurity.Snn, autn[:])

	switch check {

	case "MAC failure":
		log.Info("[UE][NAS][MAC] Authenticity of the authentication request message: FAILED")
		log.Info("[UE][NAS] Send authentication failure with MAC failure")
		authenticationResponse = mm_5gs.AuthenticationFailure("MAC failure", "", paramAutn)
		// not change the state of UE.

	case "SQN failure":
		log.Info("[UE][NAS][MAC] Authenticity of the authentication request message: OK")
		log.Info("[UE][NAS][SQN] SQN of the authentication request message: INVALID")
		log.Info("[UE][NAS] Send authentication failure with Synch failure")
		authenticationResponse = mm_5gs.AuthenticationFailure("SQN failure", "", paramAutn)
		// not change the state of UE.

	case "successful":
		// getting NAS Authentication Response.
		log.Info("[UE][NAS][MAC] Authenticity of the authentication request message: OK")
		log.Info("[UE][NAS][SQN] SQN of the authentication request message: VALID")
		log.Info("[UE][NAS] Send authentication response")
		authenticationResponse = mm_5gs.AuthenticationResponse(paramAutn, "")

		// change state of UE for registered-initiated
		ue.SetStateMM_REGISTERED_INITIATED()
	}

	// sending to GNB
	sender.SendToGnb(ue, authenticationResponse)
}

func HandlerSecurityModeCommand(ue *context.UEContext, message *nas.Message) { // check the mandatory fields
	if reflect.ValueOf(message.SecurityModeCommand.ExtendedProtocolDiscriminator).IsZero() {
		log.Fatal("[UE][NAS] Error in Security Mode Command, Extended Protocol is missing")
	}

	if message.SecurityModeCommand.ExtendedProtocolDiscriminator.GetExtendedProtocolDiscriminator() != 126 {
		log.Fatal("[UE][NAS] Error in Security Mode Command, Extended Protocol not the expected value")
	}

	if message.SecurityModeCommand.SpareHalfOctetAndSecurityHeaderType.GetSecurityHeaderType() != 0 {
		log.Fatal("[UE][NAS] Error in Security Mode Command, Security Header Type not the expected value")
	}

	if message.SecurityModeCommand.SpareHalfOctetAndSecurityHeaderType.GetSpareHalfOctet() != 0 {
		log.Fatal("[UE][NAS] Error in Security Mode Command, Spare Half Octet not the expected value")
	}

	if reflect.ValueOf(message.SecurityModeCommand.SecurityModeCommandMessageIdentity).IsZero() {
		log.Fatal("[UE][NAS] Error in Security Mode Command, Message Type is missing")
	}

	if message.SecurityModeCommand.SecurityModeCommandMessageIdentity.GetMessageType() != 93 {
		log.Fatal("[UE][NAS] Error in Security Mode Command, Message Type not the expected value")
	}

	if reflect.ValueOf(message.SecurityModeCommand.SelectedNASSecurityAlgorithms).IsZero() {
		log.Fatal("[UE][NAS] Error in Security Mode Command, NAS Security Algorithms is missing")
	}

	if message.SecurityModeCommand.SpareHalfOctetAndNgksi.GetSpareHalfOctet() != 0 {
		log.Fatal("[UE][NAS] Error in Security Mode Command, Spare Half Octet is missing")
	}

	if message.SecurityModeCommand.SpareHalfOctetAndNgksi.GetNasKeySetIdentifiler() == 7 {
		log.Fatal("[UE][NAS] Error in Security Mode Command, ngKSI not the expected value")
	}

	if reflect.ValueOf(message.SecurityModeCommand.ReplayedUESecurityCapabilities).IsZero() {
		log.Fatal("[UE][NAS] Error in Security Mode Command, Replayed UE Security Capabilities is missing")
	}

	ue.UeSecurity.CipheringAlg = message.SecurityModeCommand.SelectedNASSecurityAlgorithms.GetTypeOfCipheringAlgorithm()
	switch ue.UeSecurity.CipheringAlg {
	case 0:
		log.Info("[UE][NAS] Type of ciphering algorithm is 5G-EA0")
	case 1:
		log.Info("[UE][NAS] Type of ciphering algorithm is 128-5G-EA1")
	case 2:
		log.Info("[UE][NAS] Type of ciphering algorithm is 128-5G-EA2")
	}

	ue.UeSecurity.IntegrityAlg = message.SecurityModeCommand.SelectedNASSecurityAlgorithms.GetTypeOfIntegrityProtectionAlgorithm()
	switch ue.UeSecurity.IntegrityAlg {
	case 0:
		log.Info("[UE][NAS] Type of integrity protection algorithm is 5G-IA0")
	case 1:
		log.Info("[UE][NAS] Type of integrity protection algorithm is 128-5G-IA1")
	case 2:
		log.Info("[UE][NAS] Type of integrity protection algorithm is 128-5G-IA2")
	}

	rinmr := uint8(0)
	if message.SecurityModeCommand.Additional5GSecurityInformation != nil {
		// checking BIT RINMR that triggered registration request in security mode complete.
		rinmr = message.SecurityModeCommand.Additional5GSecurityInformation.GetRINMR()
	}

	ue.UeSecurity.NgKsi.Ksi = int32(message.SecurityModeCommand.SpareHalfOctetAndNgksi.GetNasKeySetIdentifiler())

	// NgKsi: TS 24.501 9.11.3.32
	switch message.SecurityModeCommand.SpareHalfOctetAndNgksi.GetTSC() {
	case nasMessage.TypeOfSecurityContextFlagNative:
		ue.UeSecurity.NgKsi.Tsc = models.ScType_NATIVE
	case nasMessage.TypeOfSecurityContextFlagMapped:
		ue.UeSecurity.NgKsi.Tsc = models.ScType_MAPPED
	}

	// getting NAS Security Mode Complete.
	securityModeComplete, err := mm_5gs.SecurityModeComplete(ue, rinmr)
	if err != nil {
		log.Fatal("[UE][NAS] Error sending Security Mode Complete: ", err)
	}

	// sending to GNB
	sender.SendToGnb(ue, securityModeComplete)
}

func HandlerRegistrationAccept(ue *context.UEContext, message *nas.Message) {
	// check the mandatory fields
	if reflect.ValueOf(message.RegistrationAccept.ExtendedProtocolDiscriminator).IsZero() {
		log.Fatal("[UE][NAS] Error in Registration Accept, Extended Protocol is missing")
	}

	if message.RegistrationAccept.ExtendedProtocolDiscriminator.GetExtendedProtocolDiscriminator() != 126 {
		log.Fatal("[UE][NAS] Error in Registration Accept, Extended Protocol not the expected value")
	}

	if message.RegistrationAccept.SpareHalfOctetAndSecurityHeaderType.GetSpareHalfOctet() != 0 {
		log.Fatal("[UE][NAS] Error in Registration Accept, Spare Half not the expected value")
	}

	if message.RegistrationAccept.SpareHalfOctetAndSecurityHeaderType.GetSecurityHeaderType() != 0 {
		log.Fatal("[UE][NAS] Error in Registration Accept, Security Header not the expected value")
	}

	if reflect.ValueOf(message.RegistrationAccept.RegistrationAcceptMessageIdentity).IsZero() {
		log.Fatal("[UE][NAS] Error in Registration Accept, Message Type is missing")
	}

	if message.RegistrationAccept.RegistrationAcceptMessageIdentity.GetMessageType() != 66 {
		log.Fatal("[UE][NAS] Error in Registration Accept, Message Type not the expected value")
	}

	if reflect.ValueOf(message.RegistrationAccept.RegistrationResult5GS).IsZero() {
		log.Fatal("[UE][NAS] Error in Registration Accept, Registration Result 5GS is missing")
	}

	if message.RegistrationAccept.RegistrationResult5GS.GetRegistrationResultValue5GS() != 1 {
		log.Fatal("[UE][NAS] Error in Registration Accept, Registration Result 5GS not the expected value")
	}

	// change the state of ue for registered
	ue.SetStateMM_REGISTERED()

	// saved 5g GUTI and others information.
	ue.Set5gGuti(message.RegistrationAccept.GUTI5G)

	// use the slice allowed by the network
	// in PDU session request
	if len(ue.SnssaiList) == 0 {

		// check the allowed NSSAI received from the 5GC
		snssaiList := message.RegistrationAccept.AllowedNSSAI.GetSNSSAIValue()

		// update UE slice selected for PDU Session
		ue.SnssaiList = make([]models.Snssai, 0)
		buf := bytes.NewBuffer(snssaiList)
		for buf.Len() > 0 {
			var snssaiLen int32
			var snssai models.Snssai
			if err := binary.Read(buf, binary.BigEndian, &snssaiLen); err != nil {
				log.Fatal("[UE][SNSSAI] decode S-NSSAI length error")
			}
			switch snssaiLen {
			case 1:
				snssai.Sst = int32(buf.Bytes()[1])
			case 4:
				snssai.Sst = int32(buf.Bytes()[1])
				snssai.Sd = fmt.Sprintf("0%x0%x0%x", buf.Bytes()[2], buf.Bytes()[3], buf.Bytes()[4])
			default:
				log.Errorf("[UE][SNSSAI] decode error, don't support the S-NSSAI length:%d\n", snssaiLen)
			}
			_ = buf.Next(int(snssaiLen))
			ue.SnssaiList = append(ue.SnssaiList, snssai)
		}
		log.Warn("[UE][NAS] ALLOWED NSSAI: ", ue.SnssaiList)
	}

	log.Info("[UE][NAS] UE 5G GUTI: ", ue.Get5gGuti())

	// getting NAS registration complete.
	registrationComplete, err := mm_5gs.RegistrationComplete(ue)
	if err != nil {
		log.Fatal("[UE][NAS] Error sending Registration Complete: ", err)
	}

	// sending to GNB
	sender.SendToGnb(ue, registrationComplete)
}

func HandlerServiceAccept(ue *context.UEContext, message *nas.Message) {
	// change the state of ue for registered
	ue.SetStateMM_REGISTERED()
}

func HandlerDlNasTransportPduaccept(ue *context.UEContext, message *nas.Message) {

	// check the mandatory fields
	if reflect.ValueOf(message.DLNASTransport.ExtendedProtocolDiscriminator).IsZero() {
		log.Fatal("[UE][NAS] Error in DL NAS Transport, Extended Protocol is missing")
	}

	if message.DLNASTransport.ExtendedProtocolDiscriminator.GetExtendedProtocolDiscriminator() != 126 {
		log.Fatal("[UE][NAS] Error in DL NAS Transport, Extended Protocol not expected value")
	}

	if message.DLNASTransport.SpareHalfOctetAndSecurityHeaderType.GetSpareHalfOctet() != 0 {
		log.Fatal("[UE][NAS] Error in DL NAS Transport, Spare Half not expected value")
	}

	if message.DLNASTransport.SpareHalfOctetAndSecurityHeaderType.GetSecurityHeaderType() != 0 {
		log.Fatal("[UE][NAS] Error in DL NAS Transport, Security Header not expected value")
	}

	if message.DLNASTransport.DLNASTRANSPORTMessageIdentity.GetMessageType() != 104 {
		log.Fatal("[UE][NAS] Error in DL NAS Transport, Message Type is missing or not expected value")
	}

	if reflect.ValueOf(message.DLNASTransport.SpareHalfOctetAndPayloadContainerType).IsZero() {
		log.Fatal("[UE][NAS] Error in DL NAS Transport, Payload Container Type is missing")
	}

	// n1msg payload container is UE_Policy_Conainer , type is 5(0x0101)
	if message.DLNASTransport.SpareHalfOctetAndPayloadContainerType.GetPayloadContainerType() == 5 {
		log.Warn("[UE][NAS] Receive DL NAS Transport, Payload Container Type is 5, UE Policy Container")
		err := HandlerDlNasTransportUePolicyContainer(ue, message)
		if err != nil {
			log.Fatal("[UE][NAS] Occur error when decoding UE_Policy_Container: ", err.Error())
		}
		log.Warn("[UE][NAS] DL NAS Transport-UE Policy Container, finish decoding preocedure successfully!!")
		return
	}

	if message.DLNASTransport.SpareHalfOctetAndPayloadContainerType.GetPayloadContainerType() != 1 {
		log.Fatal("[UE][NAS] Error in DL NAS Transport, Payload Container Type not expected value")
	}

	if reflect.ValueOf(message.DLNASTransport.PayloadContainer).IsZero() || message.DLNASTransport.PayloadContainer.GetPayloadContainerContents() == nil {
		log.Fatal("[UE][NAS] Error in DL NAS Transport, Payload Container is missing")
	}

	if reflect.ValueOf(message.DLNASTransport.PduSessionID2Value).IsZero() {
		log.Fatal("[UE][NAS] Error in DL NAS Transport, PDU Session ID is missing")
	}

	if message.DLNASTransport.PduSessionID2Value.GetIei() != 18 {
		log.Fatal("[UE][NAS] Error in DL NAS Transport, PDU Session ID not expected value")
	}

	//getting PDU Session establishment accept.
	payloadContainer := nas_control.GetNasPduFromPduAccept(message)

	switch payloadContainer.GsmHeader.GetMessageType() {
	case nas.MsgTypePDUSessionEstablishmentAccept:
		log.Info("[UE][NAS] Receiving PDU Session Establishment Accept")

		// get UE ip
		pduSessionEstablishmentAccept := payloadContainer.PDUSessionEstablishmentAccept

		// check the mandatory fields
		if reflect.ValueOf(pduSessionEstablishmentAccept.ExtendedProtocolDiscriminator).IsZero() {
			log.Fatal("[UE][NAS] Error in PDU Session Establishment Accept, Extended Protocol Discriminator is missing")
		}

		if pduSessionEstablishmentAccept.GetExtendedProtocolDiscriminator() != 46 {
			log.Fatal("[UE][NAS] Error in PDU Session Establishment Accept, Extended Protocol Discriminator not expected value")
		}

		if reflect.ValueOf(pduSessionEstablishmentAccept.PDUSessionID).IsZero() {
			log.Fatal("[UE][NAS] Error in PDU Session Establishment Accept, PDU Session ID is missing or not expected value")
		}

		if reflect.ValueOf(pduSessionEstablishmentAccept.PTI).IsZero() {
			log.Fatal("[UE][NAS] Error in PDU Session Establishment Accept, PTI is missing")
		}

		if pduSessionEstablishmentAccept.PTI.GetPTI() != 1 {
			log.Fatal("[UE][NAS] Error in PDU Session Establishment Accept, PTI not the expected value")
		}

		if pduSessionEstablishmentAccept.PDUSESSIONESTABLISHMENTACCEPTMessageIdentity.GetMessageType() != 194 {
			log.Fatal("[UE][NAS] Error in PDU Session Establishment Accept, Message Type is missing or not expected value")
		}

		if reflect.ValueOf(pduSessionEstablishmentAccept.SelectedSSCModeAndSelectedPDUSessionType).IsZero() {
			log.Fatal("[UE][NAS] Error in PDU Session Establishment Accept, SSC Mode or PDU Session Type is missing")
		}

		if pduSessionEstablishmentAccept.SelectedSSCModeAndSelectedPDUSessionType.GetPDUSessionType() != 1 {
			log.Fatal("[UE][NAS] Error in PDU Session Establishment Accept, PDU Session Type not the expected value")
		}

		if reflect.ValueOf(pduSessionEstablishmentAccept.AuthorizedQosRules).IsZero() {
			log.Fatal("[UE][NAS] Error in PDU Session Establishment Accept, Authorized QoS Rules is missing")
		}

		if reflect.ValueOf(pduSessionEstablishmentAccept.SessionAMBR).IsZero() {
			log.Fatal("[UE][NAS] Error in PDU Session Establishment Accept, Session AMBR is missing")
		}

		// update PDU Session information.
		pduSessionId := pduSessionEstablishmentAccept.GetPDUSessionID()
		pduSession, err := ue.GetPduSession(pduSessionId)
		// change the state of ue(SM)(PDU Session Active).
		pduSession.SetStateSM_PDU_SESSION_ACTIVE()
		if err != nil {
			log.Error("[UE][NAS] Receiving PDU Session Establishment Accept about an unknown PDU Session, id: ", pduSessionId)
			return
		}

		// get UE IP
		UeIp := pduSessionEstablishmentAccept.GetPDUAddressInformation()
		pduSession.SetIp(UeIp)

		// get QoS Rules
		QosRule := pduSessionEstablishmentAccept.AuthorizedQosRules.GetQosRule()
		// get DNN
		dnn := pduSessionEstablishmentAccept.DNN.GetDNN()
		// get SNSSAI
		sst := pduSessionEstablishmentAccept.SNSSAI.GetSST()
		sd := pduSessionEstablishmentAccept.SNSSAI.GetSD()

		log.Info("[UE][NAS] PDU session QoS RULES: ", QosRule)
		log.Info("[UE][NAS] PDU session DNN: ", string(dnn))
		log.Info("[UE][NAS] PDU session NSSAI -- sst: ", sst, " sd: ",
			fmt.Sprintf("%x%x%x", sd[0], sd[1], sd[2]))
		log.Info("[UE][NAS] PDU address received: ", pduSession.GetIp())
	case nas.MsgTypePDUSessionReleaseCommand:
		log.Info("[UE][NAS] Receiving PDU Session Release Command")

		pduSessionReleaseCommand := payloadContainer.PDUSessionReleaseCommand
		pduSessionId := pduSessionReleaseCommand.GetPDUSessionID()
		pduSession, err := ue.GetPduSession(pduSessionId)
		if pduSession == nil || err != nil {
			log.Error("[UE][NAS] Unable to delete PDU Session ", pduSessionId, " from UE ", ue.GetMsin(), " as the PDU Session was not found. Ignoring.")
			break
		}
		ue.DeletePduSession(pduSessionId)
		log.Info("[UE][NAS] Successfully released PDU Session ", pduSessionId, " from UE Context")
		trigger.InitPduSessionReleaseComplete(ue, pduSession)

	case nas.MsgTypePDUSessionEstablishmentReject:
		log.Error("[UE][NAS] Receiving PDU Session Establishment Reject")

		pduSessionEstablishmentReject := payloadContainer.PDUSessionEstablishmentReject
		pduSessionId := pduSessionEstablishmentReject.GetPDUSessionID()

		log.Error("[UE][NAS] PDU Session Establishment Reject for PDU Session ID ", pduSessionId, ", 5GSM Cause: ", cause5GSMToString(pduSessionEstablishmentReject.GetCauseValue()))

		// Per 5GSM state machine in TS 24.501 - 6.1.3.2.1., we re-try the setup until it's successful
		pduSession, err := ue.GetPduSession(pduSessionId)
		if err != nil {
			log.Error("[UE][NAS] Cannot retry PDU Session Request for PDU Session ", pduSessionId, " after Reject as ", err)
			break
		}
		if pduSession.T3580Retries < 5 {
			// T3580 Timer
			go func() {
				// Exponential backoff
				time.Sleep(time.Duration(math.Pow(5, float64(pduSession.T3580Retries))) * time.Second)
				trigger.InitPduSessionRequestInner(ue, pduSession, 0x01, nil, nil) // 0x01 means IPv4 type
				pduSession.T3580Retries++
			}()
		} else {
			log.Error("[UE][NAS] We re-tried five times to create PDU Session ", pduSessionId, ", Aborting.")
		}

	default:
		log.Error("[UE][NAS] Receiving Unknown Dl NAS Transport message!! ", payloadContainer.GsmHeader.GetMessageType())
	}
}

func HandlerDlNasTransportUePolicyContainer(ue *context.UEContext, message *nas.Message) error {

	if reflect.ValueOf(message.DLNASTransport.PayloadContainer).IsZero() || message.DLNASTransport.PayloadContainer.GetPayloadContainerContents() == nil {
		log.Fatal("[UE][NAS] Error in DL NAS Transport, Payload Container is missing")
	}

	payloadConainer := message.DLNASTransport.PayloadContainer
	var uePolContainer uePolicyContainer.UePolicyContainer
	uePolContainer.UePolDeliverySerDecode(payloadConainer.GetPayloadContainerContents())

	switch uePolContainer.GetHeaderMessageType() {
	case uePolicyContainer.MsgTypeManageUEPolicyCommand:
		err := HandleMsgTypeManageUEPolicyCommand(uePolContainer, ue)
		if err != nil {
			return fmt.Errorf("[UE][NAS] Error of decoding [DecodeMsgTypeManageUEPolicyCommand]: %+v", err)
		}
	case uePolicyContainer.MsgTypeManageUEPolicyComplete:
		log.Fatal("[UE][NAS] Error in DL NAS Transport, Payload Container is UE Policy, but type of [MsgTypeManageUEPolicyComplete] unhandle...")
	case uePolicyContainer.MsgTypeManageUEPolicyReject:
		log.Fatal("[UE][NAS] Error in DL NAS Transport, Payload Container is UE Policy, but type of [MsgTypeManageUEPolicyReject] unhandle...")

	case uePolicyContainer.MsgTypeUEStateIndication:
		log.Fatal("[UE][NAS] Error in DL NAS Transport, Payload Container is UE Policy, but type of [MsgTypeUEStateIndication] unhandle...")

	case uePolicyContainer.MsgTypeUEPolicyProvisioningRequest:
		log.Fatal("[UE][NAS] Error in DL NAS Transport, Payload Container is UE Policy, but type of [MsgTypeUEPolicyProvisioningRequest] unhandle...")

	case uePolicyContainer.MsgTypeUEPolicyProvisioningReject:
		log.Fatal("[UE][NAS] Error in DL NAS Transport, Payload Container is UE Policy, but type of [MsgTypeUEPolicyProvisioningReject] unhandle...")

	default:

	}

	return nil
}

func HandleMsgTypeManageUEPolicyCommand(uePolContainer uePolicyContainer.UePolicyContainer, ue *context.UEContext) error {
	var uePolSecMngLsContent uePolicyContainer.UEPolicySectionManagementListContent
	// decoding the byte content
	log.Warnf("section mng list content: %x\n", uePolContainer.ManageUEPolicyCommand.GetUEPolicySectionManagementListContent())
	log.Warnf("section mng list content: %v\n", uePolContainer.ManageUEPolicyCommand.GetUEPolicySectionManagementListContent())
	if err := uePolSecMngLsContent.UnmarshalBinary(uePolContainer.ManageUEPolicyCommand.GetUEPolicySectionManagementListContent()); err != nil {
		log.Errorln("[UE][NAS] DL NAS Transport decode FAIL: ", err.Error())
		return err
	}
	log.Warnf("[UE][NAS] DL NAS Transport decode Success, type: ManageUEPolicyCommand, data: %+v\n", uePolSecMngLsContent)

	for index, sublist := range uePolSecMngLsContent {
		log.Infof("[UE][NAS] start Processing %d-th ue_policy_section_management_subslist...\n", index)
		ueMcc, ueMnc := ue.GetHplmn()
		if ueMcc != strconv.Itoa(*sublist.Mcc) || ueMnc != strconv.Itoa(*sublist.Mnc) {
			// ue policy section management subslist (PLMN) does not fit the ue's PLMN
			log.Errorf("[UE][NAS] Error IE,  PLMN of ue_policy_section_management_subslist is %d%d, but it should be %s%s\n", *sublist.Mcc, *sublist.Mnc, ueMcc, ueMnc)
			continue
		}

		// Process the content
		for _, instruc := range sublist.UEPolicySectionManagementSubListContents {
			for _, uePolPart := range instruc.UEPolicySectionContents {
				switch partType := uePolPart.UEPolicyPartType.GetPartType(); partType {
				case uePolicyContainer.UEPolicyPartType_URSP:
					if err := HandleUePolicyPartTypeURSP(uePolPart.GetPartContent(), ue); err != nil {
						log.Errorf("[UE][NAS] HandleUePolicyPartTypeURSP error: %+v", err)
					}
				case uePolicyContainer.UEPolicyPartType_ANDSP:
					log.Warnf("[UE][NAS] Unhandle UE_Policy_Part_Type: [UEPolicyPartType_ANDSP(%v)]\n", partType)
				case uePolicyContainer.UEPolicyPartType_V2XP:
					log.Warnf("[UE][NAS] Unhandle UE_Policy_Part_Type: [UEPolicyPartType_V2XP(%v)]\n", partType)
				case uePolicyContainer.UEPolicyPartType_ProSeP:
					log.Warnf("[UE][NAS] Unhandle UE_Policy_Part_Type: [UEPolicyPartType_ProSeP(%v)]\n", partType)
				default:
					log.Errorf("[UE][NAS] Undefined UE_Policy_Part_Type: %+v\n", partType)
				}
			}
		}

	}
	return nil
}

func HandleUePolicyPartTypeURSP(uePolicyPartContents []byte, ue *context.UEContext) error {
	var uePolicyURSP models.UePolicyURSP
	// decode URSP first
	if err := uePolicyURSP.DecodeURSP(uePolicyPartContents); err != nil {
		return err
	}

	// sort the URSP rules by precedence value
	precedences := make([]int, len(uePolicyURSP.URSPruleSet))
	prece2URSPruleMap := map[int]models.URSPrule{}
	for index, urspRule := range uePolicyURSP.URSPruleSet {
		precedences[index] = int(urspRule.PrecedenceValue)
		prece2URSPruleMap[int(urspRule.PrecedenceValue)] = urspRule
	}
	sort.Ints(precedences)
	sortedURSP := models.UePolicyURSP{}
	for i := 0; i < len(uePolicyURSP.URSPruleSet); i++ {
		sortedURSP.URSPruleSet = append(sortedURSP.URSPruleSet, prece2URSPruleMap[precedences[i]])
	}

	// apply the URSP rules one by one to route traffic flow
	for index, urspRule := range sortedURSP.URSPruleSet {
		log.Infof("[UE][URSP] Start Processing %d-th URSP rule of UePolicyURSP...\n", index)
		log.Warnf("[UE][URSP] URSP rule: %+v\n", urspRule)
		for _, routeDesc := range urspRule.RouteSelectionDescriptorList {
			capablePduAttri := []models.RouteSelectionComponent{}
			for _, routeComp := range routeDesc.RouteSelectionContent {
				switch id := routeComp.Identifier; id {
				case models.Route_S_NSSAI_type:
					capablePduAttri = append(capablePduAttri, routeComp)
				case models.Route_DNN_type:
					capablePduAttri = append(capablePduAttri, routeComp)
				case models.Route_PDU_session_type_type:
					capablePduAttri = append(capablePduAttri, routeComp)
				default:
					log.Warnf("[URSP][RouteSelectionComponent] UE can not apply this attribution of id:%v,value:%v  on PDU session!! \n", id, routeComp.Value)
				}
			}

			// Check a single RouteSelectionDescriptor is capable to existed PDU session, then go to apply routing rule. If return false, make a PDU session first.
			exist, pduId := matchExistedPDU(ue, capablePduAttri)
			if exist {
				log.Warnf("[URSP][RouteSelectionComponent] match all RouteSelectionComponent with existed PDU session id:%v\n", pduId)
			} else {
				createPDUsessionByURSP(ue, capablePduAttri)
				log.Warnf("Invoke createPDUsessionByURSP...")
			}
		}

		// for _,traffDes:=range urspRule.TrafficDescriptor{
		// 	switch traffDes.Identifier{
		// 	case models.Traf_IPv4_remote_addr_type:

		// 	}
		// }
	}

	return nil
}

func createPDUsessionByURSP(ue *context.UEContext, capablePduAttri []models.RouteSelectionComponent) {
	var slice models.Snssai
	var dnn string
	var pduType uint8 = 0x01 //default create IPv4 type PDU session
	for _, routeComp := range capablePduAttri {
		switch id := routeComp.Identifier; id {
		case models.Route_S_NSSAI_type:
			buf := bytes.NewBuffer(routeComp.Value[3:4])
			var tmp int8
			binary.Read(buf, binary.BigEndian, &tmp)
			slice.Sst = int32(tmp)
			slice.Sd = hex.EncodeToString(routeComp.Value[4:7])
		case models.Route_DNN_type:
			dnn = string(routeComp.Value[1:]) // routeComp.Value[0] is length
		case models.Route_PDU_session_type_type:
			log.Warnln("dnn(routeComp.Value): ", routeComp.Value)
			pduType = routeComp.Value[0]
		}
	}
	// TODO: add this IE[pduType] in UE policy container
	log.Warnf("InitPduSessionRequest: pduType[%v], dnn[%v], slice[%v]\n", pduType, dnn, slice)
	go func() {
		for i := 0; i < 10; i++ {
			log.Warnf("Waiting %d-th seconds for create extra PDU session for URSP rule...\n", i)
			time.Sleep(1 * time.Second)
		}
		trigger.InitPduSessionRequest(ue, pduType, &slice, &dnn)
	}()
}

// check whether at least one existed PDU session match all RouteSelectionComponents, if ture return the pdu session ID
func matchExistedPDU(ue *context.UEContext, routeSelComponents []models.RouteSelectionComponent) (rsp bool, pduId int) {
	for pduId, uePDU := range ue.PduSession {
		if uePDU == nil || uePDU.GnbPduSession == nil {
			continue
		}
		log.Warnln("Starting Compare Existed PDU session of ue , id:", pduId)
	nextPDU:
		for index, routeComp := range routeSelComponents {
			switch id := routeComp.Identifier; id {
			case models.Route_S_NSSAI_type:
				sst, sd := uePDU.GnbPduSession.GetSNSSAI()
				if !compareSliceInfo(routeComp.Value, sst, sd) {
					log.Warnln("Slice info is not equal")
					break nextPDU
				}
			case models.Route_DNN_type:
				routeDnn := string(routeComp.Value[1:]) // routeComp.Value[0] is length
				if !strings.EqualFold(ue.Dnn, routeDnn) {
					log.Warnf("DNN is not equal: ueDnn[%v], routeDnn[%v]\n", ue.Dnn, routeDnn)
					break nextPDU
				}
			case models.Route_PDU_session_type_type:
				if !strings.EqualFold(resolvePDUsessType(routeComp.Value[0]), uePDU.GnbPduSession.GetPduType()) {
					log.Warnf("PDU session Type is not equal: ueDnn[%v], routeDnn[%v]\n", uePDU.GnbPduSession.GetPduType(), resolvePDUsessType(routeComp.Value[0]))
					break nextPDU
				}
			default:
				log.Warnf("[URSP][RouteSelectionComponent] ue does not handle match this type(attribution): %v\n", id)
			}

			// fit all route descriptor demand
			if index == len(routeSelComponents)-1 {
				return true, pduId
			}
		}
	}
	return false, 0x00
}

func compareSliceInfo(sliceValue []uint8, ueSst, ueSd string) bool {
	log.Warnf("[URSP][RouteSelectionComponent] slice info of UE PDU session is sst:%v,sd:%v\n", ueSst, ueSd)

	// decode sst
	var sstRoute int8
	buf := bytes.NewBuffer(sliceValue[3:4])
	if err := binary.Read(buf, binary.BigEndian, &sstRoute); err != nil {
		log.Errorf("[URSP][RouteSelectionComponent] inlegal slice sst:%v\n", sliceValue[3:4])
		return false
	}
	ueSst_int, err := strconv.Atoi(ueSst)
	if err != nil {
		return false
	}

	if sliceValue[2] == 0x01 { //only sst
		log.Warnf("[URSP][RouteSelectionComponent] slice info of VN Group Config is sst:%v\n", sstRoute)
		if int8(ueSst_int) != sstRoute {
			return false
		}
	} else if sliceValue[2] == 0x04 { //sst and sd
		// decode sd
		sdRoute := hex.EncodeToString(sliceValue[4:7])
		log.Warnf("[URSP][RouteSelectionComponent] slice info of VN Group Config is sst:%v,sd:%v\n", sstRoute, sdRoute)
		if int8(ueSst_int) != sstRoute || ueSd != sdRoute {
			return false
		}
	} else {
		log.Errorln("[URSP][RouteSelectionComponent] only support SNSSAI type  0x01 or 0x04")
		return false
	}
	return true
}

// ref to TS 124 501 V17.7.1, 9.11.4.11 PDU session type
func resolvePDUsessType(value uint8) string {

	if value == 0x01 {
		return "ipv4"
	} else if value == 0x02 {
		return "ipv6"
	} else if value == 0x03 {
		return "ipv4ipv6"
	} else if value == 0x04 {
		return "unstructured"
	} else if value == 0x05 {
		return "ethernet"
	} else if value == 0x07 {
		return "reserved"
	}
	// All other values are unused and shall be interpreted as "IPv4v6", if received by the UE or the network.
	return "ipv4ipv6"
}

func HandlerIdentityRequest(ue *context.UEContext, message *nas.Message) {

	// check the mandatory fields
	if reflect.ValueOf(message.IdentityRequest.ExtendedProtocolDiscriminator).IsZero() {
		log.Fatal("[UE][NAS] Error in Identity Request, Extended Protocol is missing")
	}

	if message.IdentityRequest.ExtendedProtocolDiscriminator.GetExtendedProtocolDiscriminator() != 126 {
		log.Fatal("[UE][NAS] Error in Identity Request, Extended Protocol not the expected value")
	}

	if message.IdentityRequest.SpareHalfOctetAndSecurityHeaderType.GetSpareHalfOctet() != 0 {
		log.Fatal("[UE][NAS] Error in Identity Request, Spare Half Octet not the expected value")
	}

	if message.IdentityRequest.SpareHalfOctetAndSecurityHeaderType.GetSecurityHeaderType() != 0 {
		log.Fatal("[UE][NAS] Error in Identity Request, Security Header Type not the expected value")
	}

	if reflect.ValueOf(message.IdentityRequest.IdentityRequestMessageIdentity).IsZero() {
		log.Fatal("[UE][NAS] Error in Identity Request, Message Type is missing")
	}

	if message.IdentityRequest.IdentityRequestMessageIdentity.GetMessageType() != 91 {
		log.Fatal("[UE][NAS] Error in Identity Request, Message Type not the expected value")
	}

	if reflect.ValueOf(message.IdentityRequest.SpareHalfOctetAndIdentityType).IsZero() {
		log.Fatal("[UE][NAS] Error in Identity Request, Spare Half Octet And Identity Type is missing")
	}

	switch message.IdentityRequest.GetTypeOfIdentity() {
	case 1:
		log.Info("[UE][NAS] Requested SUCI 5GS type")
	default:
		log.Fatal("[UE][NAS] Only SUCI identity is supported for now inside PacketRusher")
	}

	trigger.InitIdentifyResponse(ue)
}

func HandlerConfigurationUpdateCommand(ue *context.UEContext, message *nas.Message) {

	// check the mandatory fields
	if reflect.ValueOf(message.ConfigurationUpdateCommand.ExtendedProtocolDiscriminator).IsZero() {
		log.Fatal("[UE][NAS] Error in Configuration Update Command, Extended Protocol Discriminator is missing")
	}

	if message.ConfigurationUpdateCommand.ExtendedProtocolDiscriminator.GetExtendedProtocolDiscriminator() != 126 {
		log.Fatal("[UE][NAS] Error in Configuration Update Command, Extended Protocol Discriminator not the expected value")
	}

	if message.ConfigurationUpdateCommand.SpareHalfOctetAndSecurityHeaderType.GetSpareHalfOctet() != 0 {
		log.Fatal("[UE][NAS] Error in Configuration Update Command, Spare Half not the expected value")
	}

	if message.ConfigurationUpdateCommand.SpareHalfOctetAndSecurityHeaderType.GetSecurityHeaderType() != 0 {
		log.Fatal("[UE][NAS] Error in Configuration Update Command, Security Header not the expected value")
	}

	if reflect.ValueOf(message.ConfigurationUpdateCommand.ConfigurationUpdateCommandMessageIdentity).IsZero() {
		log.Fatal("[UE][NAS] Error in Configuration Update Command, Message type not the expected value")
	}

	if message.ConfigurationUpdateCommand.ConfigurationUpdateCommandMessageIdentity.GetMessageType() != 84 {
		log.Fatal("[UE][NAS] Error in Configuration Update Command, Message Type not the expected value")
	}

	// return configuration update complete
	trigger.InitConfigurationUpdateComplete(ue)
}

func cause5GSMToString(causeValue uint8) string {
	switch causeValue {
	case nasMessage.Cause5GSMInsufficientResources:
		return "Insufficient Ressources"
	case nasMessage.Cause5GSMMissingOrUnknownDNN:
		return "Missing or Unknown DNN"
	case nasMessage.Cause5GSMUnknownPDUSessionType:
		return "Unknown PDU Session Type"
	case nasMessage.Cause5GSMUserAuthenticationOrAuthorizationFailed:
		return "User authentification or authorization failed"
	case nasMessage.Cause5GSMRequestRejectedUnspecified:
		return "Request rejected, unspecified"
	case nasMessage.Cause5GSMServiceOptionTemporarilyOutOfOrder:
		return "Service option temporarily out of order."
	case nasMessage.Cause5GSMPTIAlreadyInUse:
		return "PTI already in use"
	case nasMessage.Cause5GSMRegularDeactivation:
		return "Regular deactivation"
	case nasMessage.Cause5GSMReactivationRequested:
		return "Reactivation requested"
	case nasMessage.Cause5GSMInvalidPDUSessionIdentity:
		return "Invalid PDU session identity"
	case nasMessage.Cause5GSMSemanticErrorsInPacketFilter:
		return "Semantic errors in packet filter(s)"
	case nasMessage.Cause5GSMSyntacticalErrorInPacketFilter:
		return "Syntactical error in packet filter(s)"
	case nasMessage.Cause5GSMOutOfLADNServiceArea:
		return "Out of LADN service area"
	case nasMessage.Cause5GSMPTIMismatch:
		return "PTI mismatch"
	case nasMessage.Cause5GSMPDUSessionTypeIPv4OnlyAllowed:
		return "PDU session type IPv4 only allowed"
	case nasMessage.Cause5GSMPDUSessionTypeIPv6OnlyAllowed:
		return "PDU session type IPv6 only allowed"
	case nasMessage.Cause5GSMPDUSessionDoesNotExist:
		return "PDU session does not exist"
	case nasMessage.Cause5GSMInsufficientResourcesForSpecificSliceAndDNN:
		return "Insufficient resources for specific slice and DNN"
	case nasMessage.Cause5GSMNotSupportedSSCMode:
		return "Not supported SSC mode"
	case nasMessage.Cause5GSMInsufficientResourcesForSpecificSlice:
		return "Insufficient resources for specific slice"
	case nasMessage.Cause5GSMMissingOrUnknownDNNInASlice:
		return "Missing or unknown DNN in a slice"
	case nasMessage.Cause5GSMInvalidPTIValue:
		return "Invalid PTI value"
	case nasMessage.Cause5GSMMaximumDataRatePerUEForUserPlaneIntegrityProtectionIsTooLow:
		return "Maximum data rate per UE for user-plane integrity protection is too low"
	case nasMessage.Cause5GSMSemanticErrorInTheQoSOperation:
		return "Semantic error in the QoS operation"
	case nasMessage.Cause5GSMSyntacticalErrorInTheQoSOperation:
		return "Syntactical error in the QoS operation"
	case nasMessage.Cause5GSMInvalidMappedEPSBearerIdentity:
		return "Invalid mapped EPS bearer identity"
	case nasMessage.Cause5GSMSemanticallyIncorrectMessage:
		return "Semantically incorrect message"
	case nasMessage.Cause5GSMInvalidMandatoryInformation:
		return "Invalid mandatory information"
	case nasMessage.Cause5GSMMessageTypeNonExistentOrNotImplemented:
		return "Message type non-existent or not implemented"
	case nasMessage.Cause5GSMMessageTypeNotCompatibleWithTheProtocolState:
		return "Message type not compatible with the protocol state"
	case nasMessage.Cause5GSMInformationElementNonExistentOrNotImplemented:
		return "Information element non-existent or not implemented"
	case nasMessage.Cause5GSMConditionalIEError:
		return "Conditional IE error"
	case nasMessage.Cause5GSMMessageNotCompatibleWithTheProtocolState:
		return "Message not compatible with the protocol state"
	case nasMessage.Cause5GSMProtocolErrorUnspecified:
		return "Protocol error, unspecified. Please open an issue on Github with pcap."
	default:
		return "Service option temporarily out of order."
	}
}
