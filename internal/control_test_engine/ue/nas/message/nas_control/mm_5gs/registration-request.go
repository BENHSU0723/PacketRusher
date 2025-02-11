/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package mm_5gs

import (
	"bytes"
	"fmt"
	"my5G-RANTester/internal/control_test_engine/ue/context"

	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
)

func GetRegistrationRequest(registrationType uint8, requestedNSSAI *nasType.RequestedNSSAI, uplinkDataStatus *nasType.UplinkDataStatus, capability bool, ue *context.UEContext) (nasPdu []byte) {

	ueSecurityCapability := ue.GetUeSecurityCapability()

	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeRegistrationRequest)

	registrationRequest := nasMessage.NewRegistrationRequest(0)
	registrationRequest.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	registrationRequest.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	registrationRequest.SpareHalfOctetAndSecurityHeaderType.SetSpareHalfOctet(0x00)
	registrationRequest.RegistrationRequestMessageIdentity.SetMessageType(nas.MsgTypeRegistrationRequest)
	registrationRequest.NgksiAndRegistrationType5GS.SetNasKeySetIdentifiler(uint8(ue.UeSecurity.NgKsi.Ksi))
	registrationRequest.NgksiAndRegistrationType5GS.SetRegistrationType5GS(registrationType)
	// If AMF previously assigned the UE a 5G-GUTI, reuses it
	// If the 5G-GUTI is no longer valid, AMF will issue an Identity Request
	// which we'll answer with the requested Mobility Identity (eg. SUCI)
	if ue.Get5gGuti() != nil {
		guti := ue.Get5gGuti()
		registrationRequest.MobileIdentity5GS = nasType.MobileIdentity5GS{
			Iei:    guti.Iei,
			Len:    guti.Len,
			Buffer: guti.Octet[:],
		}
	} else {
		registrationRequest.MobileIdentity5GS = ue.GetSuci()
	}
	if capability {
		registrationRequest.Capability5GMM = &nasType.Capability5GMM{
			Iei:   nasMessage.RegistrationRequestCapability5GMMType,
			Len:   1,
			Octet: [13]uint8{0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		}
	} else {
		registrationRequest.Capability5GMM = nil
	}
	registrationRequest.UESecurityCapability = ueSecurityCapability
	registrationRequest.RequestedNSSAI = requestedNSSAI
	registrationRequest.UplinkDataStatus = uplinkDataStatus

	registrationRequest.SetFOR(1)

	m.GmmMessage.RegistrationRequest = registrationRequest

	data := new(bytes.Buffer)
	err := m.GmmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	nasPdu = data.Bytes()
	return
}
