package com.security.appdetector

import com.google.gson.annotations.SerializedName

data class VirusTotalResult(
    @SerializedName("positives") val positives: Int,
    @SerializedName("total") val total: Int,
    @SerializedName("scan_date") val scanDate: String
)