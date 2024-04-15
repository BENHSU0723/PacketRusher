/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package convert

import (
	"my5G-RANTester/lib/ngap/ngapConvert"
	"my5G-RANTester/lib/ngap/ngapType"

	"github.com/BENHSU0723/openapi/models"
)

func NRLocationToModels(location *ngapType.UserLocationInformationNR) *models.NrLocation {
	locationModel := models.NrLocation{}
	tai := ngapConvert.TaiToModels(location.TAI)
	plmn := ngapConvert.PlmnIdToModels(location.NRCGI.PLMNIdentity)
	ncgi := models.Ncgi{}
	ncgi.NrCellId = ngapConvert.BitStringToHex(&location.NRCGI.NRCellIdentity.Value)
	ncgi.PlmnId = &plmn
	locationModel.Tai = &tai
	locationModel.Ncgi = &ncgi
	return &locationModel
}
