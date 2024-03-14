/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package convert

import (
	"github.com/BENHSU0723/openapi/models"
	"github.com/free5gc/ngap/ngapConvert"
	"github.com/free5gc/ngap/ngapType"
)

func NRLocationToModels(location *ngapType.UserLocationInformationNR) *models.NrLocation {
	locationModel := models.NrLocation{}
	tai := ngapConvert.TaiToModels(location.TAI)
	plmn := ngapConvert.PlmnIdToModels(location.NRCGI.PLMNIdentity)
	ncgi := models.Ncgi{}
	ncgi.NrCellId = ngapConvert.BitStringToHex(&location.NRCGI.NRCellIdentity.Value)
	ncgi.PlmnId = (*models.PlmnId)(&plmn)
	locationModel.Tai = &models.Tai{PlmnId: (*models.PlmnId)(tai.PlmnId), Tac: tai.Tac}
	locationModel.Ncgi = &ncgi
	return &locationModel
}
