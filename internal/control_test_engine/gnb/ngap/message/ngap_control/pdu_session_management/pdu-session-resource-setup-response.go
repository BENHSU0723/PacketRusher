package pdu_session_management

import (
	"encoding/binary"
	"my5G-RANTester/internal/control_test_engine/gnb/context"
	"my5G-RANTester/lib/aper"
	"my5G-RANTester/lib/ngap"
	"my5G-RANTester/lib/ngap/ngapConvert"
	"my5G-RANTester/lib/ngap/ngapType"
	"net"
)

/*
func pDUSessionResourceSetupResponse(connN2 *sctp.SCTPConn, amfUeNgapID int64, ranUeNgapID int64, supi string, ranIpAddr string) error {
	sendMsg, err := PDUSessionResourceSetupResponse(amfUeNgapID, ranUeNgapID, ranIpAddr)
	if err != nil {
		return fmt.Errorf("Error getting %s ue NGAP-PDU Session Resource Setup Response", supi)
	}
	_, err = connN2.Write(sendMsg)
	if err != nil {
		return fmt.Errorf("Error sending %s ue NGAP-PDU Session Resource Setup Response", supi)
	}

	return nil
}
*/

func PDUSessionResourceSetupResponse(ue *context.GNBUe, ipv4 string) ([]byte, error) {

	// check hostname(Error in docker if using hostname)
	nameIp, err := net.LookupHost(ipv4)
	if err != nil {
		return nil, err
	}
	message := buildPDUSessionResourceSetupResponseForRegistrationTest(ue.GetAmfUeId(), ue.GetRanUeId(), nameIp[0], ue.GetPduSessionId(), ue.GetTeidDownlink())
	return ngap.Encoder(message)
}

func buildPDUSessionResourceSetupResponseForRegistrationTest(amfUeNgapID, ranUeNgapID int64, ipv4 string, pduId int64, teid uint32) (pdu ngapType.NGAPPDU) {

	pdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
	pdu.SuccessfulOutcome = new(ngapType.SuccessfulOutcome)

	successfulOutcome := pdu.SuccessfulOutcome
	successfulOutcome.ProcedureCode.Value = ngapType.ProcedureCodePDUSessionResourceSetup
	successfulOutcome.Criticality.Value = ngapType.CriticalityPresentReject

	successfulOutcome.Value.Present = ngapType.SuccessfulOutcomePresentPDUSessionResourceSetupResponse
	successfulOutcome.Value.PDUSessionResourceSetupResponse = new(ngapType.PDUSessionResourceSetupResponse)

	pDUSessionResourceSetupResponse := successfulOutcome.Value.PDUSessionResourceSetupResponse
	pDUSessionResourceSetupResponseIEs := &pDUSessionResourceSetupResponse.ProtocolIEs

	// AMF UE NGAP ID
	ie := ngapType.PDUSessionResourceSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.PDUSessionResourceSetupResponseIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)

	aMFUENGAPID := ie.Value.AMFUENGAPID
	aMFUENGAPID.Value = amfUeNgapID

	pDUSessionResourceSetupResponseIEs.List = append(pDUSessionResourceSetupResponseIEs.List, ie)

	// RAN UE NGAP ID
	ie = ngapType.PDUSessionResourceSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.PDUSessionResourceSetupResponseIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)

	rANUENGAPID := ie.Value.RANUENGAPID
	rANUENGAPID.Value = ranUeNgapID

	pDUSessionResourceSetupResponseIEs.List = append(pDUSessionResourceSetupResponseIEs.List, ie)

	// PDU Session Resource Setup Response List
	ie = ngapType.PDUSessionResourceSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceSetupListSURes
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.PDUSessionResourceSetupResponseIEsPresentPDUSessionResourceSetupListSURes
	ie.Value.PDUSessionResourceSetupListSURes = new(ngapType.PDUSessionResourceSetupListSURes)

	pDUSessionResourceSetupListSURes := ie.Value.PDUSessionResourceSetupListSURes

	// PDU Session Resource Setup Response Item in PDU Session Resource Setup Response List
	pDUSessionResourceSetupItemSURes := ngapType.PDUSessionResourceSetupItemSURes{}

	// PDU Session ID : This is an unique identifier generated by UE. Can’t be same as any existing PDU session.
	pDUSessionResourceSetupItemSURes.PDUSessionID.Value = pduId

	pDUSessionResourceSetupItemSURes.PDUSessionResourceSetupResponseTransfer = GetPDUSessionResourceSetupResponseTransfer(ipv4, teid)

	pDUSessionResourceSetupListSURes.List = append(pDUSessionResourceSetupListSURes.List, pDUSessionResourceSetupItemSURes)

	pDUSessionResourceSetupResponseIEs.List = append(pDUSessionResourceSetupResponseIEs.List, ie)

	// PDU Sessuin Resource Failed to Setup List
	// ie = ngapType.PDUSessionResourceSetupResponseIEs{}
	// ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceFailedToSetupListSURes
	// ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	// ie.Value.Present = ngapType.PDUSessionResourceSetupResponseIEsPresentPDUSessionResourceFailedToSetupListSURes
	// ie.Value.PDUSessionResourceFailedToSetupListSURes = new(ngapType.PDUSessionResourceFailedToSetupListSURes)

	// pDUSessionResourceFailedToSetupListSURes := ie.Value.PDUSessionResourceFailedToSetupListSURes

	// // PDU Session Resource Failed to Setup Item in PDU Sessuin Resource Failed to Setup List
	// pDUSessionResourceFailedToSetupItemSURes := ngapType.PDUSessionResourceFailedToSetupItemSURes{}
	// pDUSessionResourceFailedToSetupItemSURes.PDUSessionID.Value = 10
	// pDUSessionResourceFailedToSetupItemSURes.PDUSessionResourceSetupUnsuccessfulTransfer = GetPDUSessionResourceSetupUnsucessfulTransfer()

	// pDUSessionResourceFailedToSetupListSURes.List = append(pDUSessionResourceFailedToSetupListSURes.List, pDUSessionResourceFailedToSetupItemSURes)

	// pDUSessionResourceSetupResponseIEs.List = append(pDUSessionResourceSetupResponseIEs.List, ie)
	// Criticality Diagnostics (optional)
	return
}

func GetPDUSessionResourceSetupResponseTransfer(ipv4 string, teid uint32) []byte {
	data := buildPDUSessionResourceSetupResponseTransfer(ipv4, teid)
	encodeData, _ := aper.MarshalWithParams(data, "valueExt")
	return encodeData
}

func buildPDUSessionResourceSetupResponseTransfer(ipv4 string, teid uint32) (data ngapType.PDUSessionResourceSetupResponseTransfer) {

	// QoS Flow per TNL Information
	qosFlowPerTNLInformation := &data.QosFlowPerTNLInformation
	qosFlowPerTNLInformation.UPTransportLayerInformation.Present = ngapType.UPTransportLayerInformationPresentGTPTunnel

	// UP Transport Layer Information in QoS Flow per TNL Information
	upTransportLayerInformation := &qosFlowPerTNLInformation.UPTransportLayerInformation
	upTransportLayerInformation.Present = ngapType.UPTransportLayerInformationPresentGTPTunnel
	upTransportLayerInformation.GTPTunnel = new(ngapType.GTPTunnel)

	// generates some GTP-TEIDs for UPF-RAN tunnels(downlink)
	/*
		var aux string
		if teid < 16 {
			aux = "0000000" + fmt.Sprintf("%x", teid)
		} else if teid < 256 {
			aux = "000000" + fmt.Sprintf("%x", teid)
		} else {
			aux = "00000" + fmt.Sprintf("%x", teid)
		}
		resu, err := hex.DecodeString(aux)
		if err != nil {
			fmt.Println("error in GTPTEID for endpoint UPF-RAN")
			fmt.Println(err)
		}
	*/
	dowlinkTeid := make([]byte, 4)
	binary.BigEndian.PutUint32(dowlinkTeid, teid)
	upTransportLayerInformation.GTPTunnel.GTPTEID.Value = dowlinkTeid
	upTransportLayerInformation.GTPTunnel.TransportLayerAddress = ngapConvert.IPAddressToNgap(ipv4, "")

	// Associated QoS Flow List in QoS Flow per TNL Information
	associatedQosFlowList := &qosFlowPerTNLInformation.AssociatedQosFlowList

	associatedQosFlowItem := ngapType.AssociatedQosFlowItem{}
	associatedQosFlowItem.QosFlowIdentifier.Value = 1
	associatedQosFlowList.List = append(associatedQosFlowList.List, associatedQosFlowItem)

	return
}
