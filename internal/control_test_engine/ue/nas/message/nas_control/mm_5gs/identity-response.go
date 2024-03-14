/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package mm_5gs

import (
	"bytes"
	"fmt"
	"my5G-RANTester/internal/control_test_engine/ue/context"

	"github.com/BENHSU0723/nas"
	"github.com/BENHSU0723/nas/nasMessage"
	"github.com/BENHSU0723/nas/nasType"
)

func IdentityResponse(ue *context.UEContext) (nasPdu []byte) {

	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeIdentityResponse)

	identityResponse := nasMessage.NewIdentityResponse(0)
	identityResponse.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	identityResponse.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	identityResponse.SpareHalfOctetAndSecurityHeaderType.SetSpareHalfOctet(0x00)
	identityResponse.IdentityResponseMessageIdentity.SetMessageType(nas.MsgTypeIdentityResponse)
	identityResponse.MobileIdentity = nasType.MobileIdentity(ue.GetSuci())

	m.GmmMessage.IdentityResponse = identityResponse

	data := new(bytes.Buffer)
	err := m.GmmMessageEncode(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	nasPdu = data.Bytes()
	return
}
