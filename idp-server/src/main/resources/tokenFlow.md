# Basic FLOW 
Log-In attempt using egk with DN 'CN=Juna Fuchs, GIVENNAME=Juna, SURNAME=Fuchs, OU=X114428530, OU=109500969, O=AOK Plus, C=DE'


## Authorization Request 

```
https://<FQDN Server>/<AUTHORIZATION_ENDPOINT>
    ?client_id=eRezeptApp
    &response_type=code
    &redirect_uri=http://redirect.gematik.de/erezept
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'gADuchxIIKpyzG7oMEHI'>
    &code_challenge=<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: 4YgrFyOto2KTgeM7LREJ_pmtnT_hOL-Tn7eGOHqtHRc>
    &code_challenge_method=S256
    &scope=e-rezept+openid
    &nonce=<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'Ft344624J2YoCnve0DmK'>

```

## Authorization Response 

```
200
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Transfer-Encoding=chunked,
Date=<Zeitpunkt der Antwort. Beispiel 'Thu, 04 Mar 2021 15:07:30 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "challenge": {
    "rawString": "eyJhbGciOiJCUDI1NlIxIiwiZXhwIjoxNjE0ODcwNjMwLCJ0eXAiOiJKV1QiLCJraWQiOiJpZHBTaWcifQ.eyJpc3MiOiJodHRwczovL2lkcC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJzbmMiOiJVby9kSUU1Y2R6SzdEaWdpWFdsS0hTZTViZ0JTZjZ3MXBzQ1pURlBwVlVRPSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJ0b2tlbl90eXBlIjoiY2hhbGxlbmdlIiwibm9uY2UiOiJGdDM0NDYyNEoyWW9DbnZlMERtSyIsImNsaWVudF9pZCI6ImVSZXplcHRBcHAiLCJzY29wZSI6ImUtcmV6ZXB0IG9wZW5pZCIsInN0YXRlIjoiZ0FEdWNoeElJS3B5ekc3b01FSEkiLCJyZWRpcmVjdF91cmkiOiJodHRwOi8vcmVkaXJlY3QuZ2VtYXRpay5kZS9lcmV6ZXB0IiwiZXhwIjoxNjE0ODcwNjMwLCJpYXQiOjE2MTQ4NzA0NTAsImNvZGVfY2hhbGxlbmdlIjoiNFlnckZ5T3RvMktUZ2VNN0xSRUpfcG10blRfaE9MLVRuN2VHT0hxdEhSYyIsImp0aSI6ImVmZDI3M2M4ODE2ZWQ0NjIifQ.hegEGi6Aedjk-Vv7ijqUUs3Uho-kb02lZtW0pvVs4g1hrDHGocOWzk6O3eLQdWGiqxL244Z4VU5eLpfFwugTzw"
  },
  "userConsent": {
    "requestedScopes": {
      "e-rezept": "Zugriff auf die E-Rezept-Funktionalität.",
      "openid": "Zugriff auf den ID-Token."
    },
    "requestedClaims": {
      "organizationName": "Zustimmung zur Verarbeitung der Organisationszugehörigkeit",
      "professionOID": "Zustimmung zur Verarbeitung der Rolle",
      "idNummer": "Zustimmung zur Verarbeitung der Id (z.B. Krankenversichertennummer, Telematik-Id)",
      "given_name": "Zustimmung zur Verarbeitung des Vornamens",
      "family_name": "Zustimmung zur Verarbeitung des Nachnamens"
    }
  }
}
```


### Challenge Token:

```
{
  "alg": "BP256R1",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1614870630'>",
  "typ": "JWT",
  "kid": "idpSig"
}
{
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'Uo/dIE5cdzK7DigiXWlKHSe5bgBSf6w1psCZTFPpVUQ='>",
  "code_challenge_method": "S256",
  "token_type": "challenge",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'Ft344624J2YoCnve0DmK'>",
  "client_id": "eRezeptApp",
  "scope": "e-rezept openid",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'gADuchxIIKpyzG7oMEHI'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1614870630'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1614870450'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: 4YgrFyOto2KTgeM7LREJ_pmtnT_hOL-Tn7eGOHqtHRc>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: 'efd273c8816ed462'>"
}
```


## Authentication Request 

```
https://<FQDN Server>/<AUTHORIZATION_ENDPOINT>
Multiparts:
signed_challenge=eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJjdHkiOiJKV1QiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoibUxlVDcwTHlZa2pocm1zX1ZVbXI5aXRoYThKNFdlMUNYYnNJajhDZ2l0byIsInkiOiJPdW11Q09nSnR4dmtMMWRnMG1FempzNWRuNXFLcGJwaHNMRXNKbXBNR3djIiwiY3J2IjoiQlAtMjU2In19.d7zrvA3_hexKMTmmtrxBhwJQUYjyrNeDoRJ-etlUmcStxKMYjUg8Vg.eiG9Ed5bjPH099vV.8G48XdtcP5qR77pVlXoIEZbyaYdwTAxgOeDwokuOao3OJczBxs5SVkgufgs8nUK28XvEWvJ6oGfxeMef-R6JmZlFkTCCHRceUjIXbyaoNS8fM19kgTwBgDs6cqP10KmiTdpKbSy4O337nRwNN2CCiTqiOIpkWKN58kdN6do44Tkhu6nr-BnMe3iA7xMOZ3jmmOqagaEZKeArYjjUrHl_yr_iaZ9EfyZ2GqOpa8nJZ04oRJzOLdr-hyJCfBBz8TEwkA5vuxJVoYDK6JRl4H8IKr4TrbgOp6aK8dia270b-XsAXWOXMw0mdbvG7nOyD8JtsPfhqctkuNiS3wypec0WuskBVXqE07gzE5j3jwFEsIhRF8rIFOmpeqTfK3v5mc30y-lIsZbTCDk0qNq2ddPYEtWyu_rMX3QG2PnkuHaAiguGGmD0_cLgJ5TLS0OfZkFm5dvVd8BdUI9VYUjukfAX1TtKHJlE_HVv86DByOWBIXhV_DblNcVxfnrGoWCTMBM6BQe85BFZGjEs0FrV6aq-MN_yKlScGZlzLz_VOqB1FggR27wPrndtpv3H9asTlhLXOqZcjEfKLEgkYl5t0nUuAcPMAlQBLTXTYAeTPZfoK2_Yvvk706CXTbTZhlLfkw2zK6QI5jLRN2DYLJmElXdJ_IRhjOlfnfs8CjwDtpkEHpVs2A5vAUJXxwadvJux_boO1_Nc384ys7hTTom0h_PVIV08OJ6dIHzy2jPE-M2J79DnBUHZ4JQLrpNUGp5igAD2u10FCarAZYv_BEHWZvNqB7b_hOb7ZqCwzuZmKeDCY_WbgOUm2YolmvY8oM90DGj9JBVQjQ7c5RduL8c9WEydm2Wm7y2MVgXEDwHFl9bYOEJDzGGhhMFXf3CoPZ8nqV7wJGiZcw1VNcgEhOPRtT304EiAsPMckfg7R6bq11Uh41MOSxlP-fLl1Fn4bBnIM_gVoRzafk1g-NwEBPe4sasF-lUr_fLoOFQYU-jBgyDPm21ZpXffbPIhEwi5qUsp6nCUHhINV3SgzdBJT0c1rNlHfNPa-vqoBI0lRziTpsbeFVHpwyxFQGhJDMVQFUk0evdBAa4UbvGlHhrIYvNppn2QOLwVQZmM6PmK9i6ZBk6KZHlDSdrTSbQoPJELB1t6d6-D5MEHNJvkOtqxTwov8dTx9wMCYnm75fHPdShaTZOh2oWzg6txZSUci_lxdGW9GqttWWGL2hc9kesNp_b-bAtNQ8oXm4_BJKvQd_2Ug2ECp-PBw-ym2r7r10g2KFuLSYX_v0N3Nu9dHvF5jkDsm0-yxgjWuxLe7H5RnmFptTuIrqI0vxEK1toFbcLU5kvHa5aLzHVrvSyDnuQYOq8yaWA9OcaPfgaIvZoal5xjnfj9Ahp1PNre02A8g7LVk_SdUGvJyfgUHIevIiUN8GxTmw0D9EtqsBu522tCxWzHxVG3GXMWcLnwbyjpsiox2Lrr8tVpWDp66uEAYpPjac3swccmpLTxmX_LXzcWCnzbHtD91yBevzjJOwzf2cK1Y1gJJr8MliRQuMSa19WwLsU-XQs2iUj4eUX4Ah_0XyC1uC_XzVN4h7FBSWxanVlZVH1Fox39Mu1nJf0UvyZ40cdM4Hmy2eqZK71acih-E2JdXQehsLB1SK6DSCk2MHB59xBNP2ncPFPuEcXn2diRT_PGXoo212CwrKwqgAcXrX5g9a-9vOqUr9OwmdH-Ynxpzriv9rrkploYyWw_29pfh9WxGASaHuPb-3sZiCpTwmzQ24qFecNFFef1O7g9EkLD8ICe1UnI_onreI70VsrF2tgG4PssMBoWlbphO8clJqr_1dO3yDFetB-w_V3C-U0aJXsfuPgoIWs5sKJtGNH0xSF7lT2fXPpmGqiijawrtmhMGnwXwZRnDwVk_f4WZWBMmas2YQrLOHP8VNT8PWXzkpRL8dHz9QJoy0XUIbyuyvped66VpOPnjOA_UAiLZhToJp-IsfZsJ4yXe8vS5kSjX6wbyOqs12LQvfLjyaerjrWrwO6GfBhdbaaWCzwmwN-XoIEp0rSgsR6TEBLgeDmAHE5_JtaRq4_nKFP9sUt46QikaRUGqpCsOogBmNE-2ickAXIKHyE0AeZsiE59oHIqXdezuASuVkTZffuww9mkX9-xYKXSZB7u_w0oMvC2FoEvc18vZ_-bwGA-JK7J2yqkXj6DJiKPlgAfh3iSh6nI6A9PeIDlAmqqxzG2NU6D0FOfUH_7N-ewKHpn8k2IE242KEJDezS9fhuHNqjUVWhiKLd7HGOCEc6jNI2KlRiH8FlEycvTP8ZNI2IqEzLJ2vMkEGuu9Tg2KlG-vbGAaae6ntUmhSoFJ_LALRXHpPXoIY2BGirkTspfyoLp2Hr7KVCrjW5_z4iSLiL9rdj_0hhtzX_yjgWZdUHDw5H_cPGF0xe75klT-nvAs1AS0ZYb3ru8ygLqzKDY7un-KpsN7j_Fhz8CI6oA2EeDgh-D4BjM3HnG3548ZzmCc_lD0EFdkC8HKiMyHMsk9p5C-R8E-8NTwmCFFEH02Tfw5vKjsG5QUKgEv5S4OSHW5B--3WH8WSb7MSKGUdGNk2it0XWNGR6BOYLWnNJLCOea1vRgoyLwQcR6aQd5EOJqDx5L8_74lsdNfGawNKml8YrQ8_d2qT86DYqnwPyfY8L2SzIMnZ9vmDiWB-oXrysxVBBKuwpdEWz-VEnAGVFUVgpiGywpGXmhVC6hJvP70mwWQ1nPfYuO1I2Nb0pMB9aBTbUrF-FqtQWzcBn2IYCEVq_fXWJA2jAm8wQcost47iHEVYMUov3frYBJUQnXvc9ZDWQtWldGnaMaZQbaso6iiCU6auwQxnVTJ-V86Eu3FOrJH5ZI4l2cCsqdbpL_zclXpNvn-BMLA6lyCwJAAA418V4aUl2f_M6jSWPYegRCeu2MIZxpL-Anri7L5JV4MosUZJZZE6MIfHO2gx-lC5RHaadFuw1uiedRlY345X8HX0zpsQCRYmM7ZoVghAH5GkguGA9qryCQ2F7gwP3D3ej-V5BgIs7hbAM5aHCOHFO5Yj_H3j82EfMt1ZcNFJSn60A2Vr9GZap8lIDA_SajeLAvA-IfxQ7vN-ybtxbU2C0O7FpKL2M0fsjXucwGRuBMS7pff3t74eWP8jM6GVkHS9ilBecmGksonCJe_X0Hl89HIh7njCuevUp_mR41NI-hgSu8RQfZO3Ac1dGhlc7csWvnEiS7TFukR-18-d4yocu_F1JBgvJLoHsNmpFhvMVaak3NX-eekpeQqbwqMVHvfDmthej6eDrlDPAat9UUEL4WnyvIu9nW5oWcRFLg_eBhvQbpMuUja8lzEk2dEiUIoLvaKy02CfbL1wHXoeWnf8ePemO5DI-Rngp4x27VlsSGRdKnbRKCks53xsSFTm2J7OYnPHhBuCvbBM1gTAsBPA-nUO_0aQRBYbBEdHCOBAPE042nZ3A1qj9R-6Mt70lQ5-d69Rp7uQ.-b0MZg8HAPJL0ZHdTpW5cA

```

### Challenge Response (Encryption Header):

```
{
  "alg": "ECDH-ES+A256KW",
  "enc": "A256GCM",
  "cty": "JWT",
  "epk": {
    "kty": "EC",
    "x": "mLeT70LyYkjhrms_VUmr9itha8J4We1CXbsIj8Cgito",
    "y": "OumuCOgJtxvkL1dg0mEzjs5dn5qKpbphsLEsJmpMGwc",
    "crv": "BP-256"
  }
}
```


### Challenge Response (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "cty": "NJWT",
  "x5c": "<Enthält das verwendete Signer-Zertifikat. Beispiel: '[
                                                              "MIIC+jCCAqCgAwIBAgIH..."
                                                            ]'>"
}
{
  "njwt": "<enthält das Ursprüngliche Challenge Token des Authorization Endpunkt>"
}
```


## Authentication Response 

```
302
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Location=https://<FQDN Server>//erezept/token
    ?code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE0ODcwNTEwLCJjdHkiOiJKV1QifQ..bHIpUnczdCNKnXn4.5iSkdBQ_lUnmHSUoCxz7Ap51DZfeDKdNUTczQ1n0oBIEtIcp2jsK9iG0WXJewiMl9KED4MWx2-l7GZzXWIS-EjQ5VaNEiOyhWUcUdESf3CGVuzhVBL0RqB7On_adylrPQ4NHMqi7csf1WoPybCPioPDPaPKV1DJVcGcNskuRIam331JglGvdn8U2lYOBjGy-Jdna11OHCVy-PDvQlOUC6c1ycyIVmZD7O5bYt8lfSeR8Kak7ipX_dmRdCmgJ2D0u2eYfNkzCFUgkE_qrXxEIOUlNVerUQAG_b0wrnDLF94xlPdjr3d0ck4Xs2wioA_vwdoWNRVhrmx_XuydhFWYIBbCDAHd_R5mxJUT_y9kHa7PwtyuFvoYAQZlAZy9-I2nzsXk2N7cefDtq5R2PQKWOqkywTuzBTgSQkZchE-xzTYnSKafo0BKb7ThU-rlxhGJTLVDmoQW9lHj90kPSa4ve1HKZyrN7VrTk-2bbnlGHvyYxqR2Sb_v5WlZBEbCHtala96lCGQfTFi8A2VjxmdqrXl7IkhRWLrNbq-u5VFLgGq9hZaFGM56FUYSr9rOtyTEkVCfn_Iwtik5GWX0-RIEL7Ozgs7KXdVB6a3VHpRH_bUM_vVA9wEK3oSbUD64oHtb_TFGvN2259n5yRZ2J_GnAbO6enOOP_7nKwUniSnEKRjLzbgq9HdPSL1KHELJL4ZN10YwDOWHMnWa3a-v2dGqlXL_e13vItNK0cg7cABeqVk8WbY1vQB9bRpz2Or_idX3vpymUTlaMxN2sFFW7njM3VLr2W2T_Se8KjthWR8L5KDxHpE7wqia-HhOFhoS4LA5ctsqOfJevwpU3GRf2yhaWqaAJBBMWZrpqNBRLxbRR7J40uFvcEuxyVvOBRNuOW4R2SzdBOeMznhMEqS05YYdC0nFDj2M_dXPoV4vrUuvB0zaJDqBUk4567Z0vl3_mlg_Sq5fqiDOLUTOgR-YxZtJjXRVGcny9Q57Gc1fJhmIZoufvjjkYGMw5dM_y9puUzjofJFg1oSe4_3a-fx6HCz-7CEaNkaB2tFLfTKuUEQU8ntjEdr5Ew9_rCYuqw3GIxeFZYWOkAVUEgybZ_9JmQj8PzL8QnKq0DBwwtgEQbcFUSdipY37Ln1rx0m61HOMC4Cgtg9iJ3jXXQcQzC7ik51t-Pduz2KJ8vmAdS2g_3WLLCEM9HWAsF19fUeRVG6wWxVI5wpDP6zvQuA3XUBB49WZJ3kIpB9HsI6sA2ZE_g7Jt12X3kDfmLx_3ZtuKxng7cdzsAKeWFy3J3WbtgKj2UrzR6KNIUVVE2xS1Xt6ohV1NqVt52u2VyuVMnrdZnzyKz7orQtMYXCY.3nHlZSPdHeql8ok4yUCp0g
    &ssotoken=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE0OTEzNjUwLCJjdHkiOiJKV1QifQ..hTTZs5ciwOhCH9h5.nt7LWyF68hTuXKv1BQrW3c1rRJzSEPyI9p3nbEJgDalEdix37MMXrY5xyrK2xGbHV_6AdKHPSPBIaniqan5mRkxiY46Q3_8AiH9exDESDLX1OwQSA9PWHcHWxg7ukDCJkN0F1NRwir553lVryZIJpGDwklKa0hlHyNAqR1XNzgvSLMN8P9YYtZTFcFiAqPRAMVSrrh6Qu3pslHq3eUdO5lC8lHJC6UnjsJJirD-sIhEUhdWhVMVdJWV2AdbDK_4WryiWxwyinWCpymQR7_p5J6cn0DyVLTM07x2XLhSY2ehaA83hdUpxJHxCG6VjFqlB2DCpNsR22nr1shuhGSMPxCYMHGgw-kMvSumjrlfKlcvF2ms8zGwskf6o0GQqgOnHllYxA3fRvigMC3tT8RxKVzG3pbelpn3dWg4FS0Z41JsSxquRvAVDnA4-M2k9H-7ncUqV_4iUDm71NWmz7urA71hbB0sDlbk-FH8KPWCHT0yIlSmhYhewhU1Alexw9KYTVml3VK4_mVct403rV1b8b2ZnCT8owQ28lxrMbN18Hr6DJch14p--_sce2MZC2yf2wWtxxcb8wxtwMOMZ3BuNYie7bvxMpaDA-NJkcXrQU563G4RfxQoZ7I_TGB_M-0rrog9k62Syuee1UIbRxVOMOmcHlfYu6402wITIWja151cQiB1ZNFioSU8s7KzYsoHg2mHzr02m2oUDmdU4vWiSXjuPPIjf1Jf_-_tru0k1IymWlMHurJzfjiQs3H0YG99n_6wgK-8D9hahHfgskryLbfLKUBma23uXIj7_mgZV3aCxjP14CBBHHfZaPA6s4dmWtiv5KwYH3oTBC_x17IOqr4Kg2waFu7f600H9JruwJvcoTIvvf-2bjIxfAkAGJjnbpiDHg2GmbZTXfpBpGt-pqA0w1iHcAQp4rfEe0LdHbVfZPrOCkM-wW_LOO8WgklM_SrQw_P8lzh6-41AYYFxPeaczEcWk8kTccfF3rc7n5B8hoMIR4dkl3bD9brmjLRTCKnR7yTXRqEUlX1QWfpxVXwkF5hJrPm_mD5UqK2c4JiZRHDEhQT1empEGBIEIDygCH04dww0WG9MMdBKcZmhKZy4lLf4_Yh5qUbUTDf1def5QYzQ4Il6I5CRvvlT0S7ncBBxp4czlgn1yxjWqWqBMhl7TV8yFowtbpJWMAVGal0H9IsGrygN8-1hDHx5M9rJpkfTja7VCdUiRYYhQHKCULNCXipYfhYilsytE373Vn8AOYKzFY73aNc9AamzSXZP3P7HG45X1KnT8ziYVz32VYW3I1cIed7dwf-EpJ35d9v6dZTpzgjbov15xSgpvlOtEo7eqSp6E35-IttBbOx8d1iAqJ7k7d8pT1iVurVa_KMdYJuIs3o4PgkIrBZFNmaJDDNggQhecwWae9rvhqUa0OP0NHNe5sQbmNY-dvcHJu1ueDQ9wHowt8zVJ5S35NzizgW_0XTOsQYHwvFLB6Jrqpqkgqk9GzdvLR9U0itgxk8t5Nqax3t8kJxYXm5PuFEkeI2x-8QAmhLspTDIw1bMvL_lb_EVHSEQCtAivfd1f7Rqx-8A3GDxuZcKvRpbzNuEyamEa_7y3komNdq1yVHabVJyEyJwDd_9Y6Adsq0U1nMCJYrxeNqLslhsEDPEVrg-EnaWQZ1zNTbZVcfCVJ-mqjmfdeAG_zhTOOFtoNXRGNBvoW38wk2SDTVPil4TTxf46gT9Zk9nADfze99qlUCp-1Wiw9jiyb0NdoylPVIxJSyACpGxwza5w32TuRzbUFI18gJYpze9C-d3uzp2FyORxb2o-nQlrrPi1SQo4LQ_Oj5u62qh3Oji2OQChMG6FBiudNV75iYWu5OMPoQX40yTrRUA9TwXoY6r6QxMqQZf06a3k-GjqvQy_fmyjw8Ja815T7gkI9prHUQppVqTDVLUyKg9zu_ouCRhGs_jV5co3IfbGy5khSiZS5w4tpJUCBqPKQbnayUvXUgz_JX71uzm7YwDwoknsUU7bWx1LtLchmKPMelzUMEAkOfu6RIRHXzcRJTLf28vQFM78UMx4SE4D24m9nsN9sUkZ33oasx11yUvEchNNse24O0K3Ql7Hp0k6wqW5Iponx7Bbe8CrITk8FmLOeGvjXRphSa6QD80wX5bgDQr150EsozjbfbveQHAdMYzWpJ-5ZBOQqNp7AS9ltPQLBC1cNp88kBXauW4ZKdKL_PxfMpmsT3za0LZx5BQKwRPOdJ8FVSs_R7gWDNa6VF6O-LOvWeYmQ4zCrtla5t9a6ONML_8hIaZihpdc4nJSybxQOEgAx9ALWc33eucJKdTCInn1ZDb_2jM4tOZ1dytOWV5DuiAto6kgBbuTy1inCuLJWJRLU8AwUTbGNfUuKjFRJNlJKNDn2DsS3HEb3u_UfdxTqCGZBvbtt9Dkt8uO66aTEGsPlgeBuZjWdIZNiCuWyeiFhbWfTBmmdQB1LpZccq0bauGWKacFPCpBlbeYoiCKLgtviYzgiK823kKuS-6v2oCoMhjGzWaGnMXfyFSW-5AHSiuc5SrN4Ukopp0eOs_QXe5QXqzqpgxaRG8m4S6g55eUCpgqfFwkQlabUehM6ikjEl-DLTAHdRHwEsFhRl2X027guX2ES7XUr6HObTUlF6mPsCipUBkJE9PBiqUUkepKS_c8NG5AlDwr66ZKerfTztkzPp_QdLGJhdNOEpRS1hG6p2h2OeLwoJv1LdBO4IZSHU89Lu5ipTzXHFccEdWTOwXK7Gj96GTTc2YoQsm9hQeco6HmoIb7LA0WYIaoWNEQ43BJiFkEjRvoSlJDmVz_bNOGpj9lhuTK5pGdUTCmbtU.bMme2nNMaP9z3W4x4rQDAQ
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'gADuchxIIKpyzG7oMEHI'>,
Content-Length=0,
Date=<Zeitpunkt der Antwort. Beispiel 'Thu, 04 Mar 2021 15:07:30 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


### Authorization Code (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 1 Minuten. Beispiel: '1614870510'>",
  "cty": "JWT"
}
```


### Authorization Code (Decrypted):

```
{
  "alg": "BP256R1",
  "exp": "<Gültigkeit des Tokens von 1 Minuten. Beispiel: '1614870510'>",
  "typ": "JWT",
  "kid": "idpSig"
}
{
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'kudni0S8RT6NEjEsUYn2'>",
  "code_challenge_method": "S256",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "token_type": "code",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'Ft344624J2YoCnve0DmK'>",
  "client_id": "eRezeptApp",
  "nbf": "<Der Token ist erst ab diesem Zeitpunkt gültig. Beispiel: '1614870450'>",
  "scope": "e-rezept openid",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1614870450'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'gADuchxIIKpyzG7oMEHI'>",
  "exp": "<Gültigkeit des Tokens von 1 Minuten. Beispiel: '1614870510'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1614870450'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: 4YgrFyOto2KTgeM7LREJ_pmtnT_hOL-Tn7eGOHqtHRc>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '2413217074c35aff'>"
}
```


### SSO Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1614913650'>",
  "cty": "JWT"
}
```


### SSO Token (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1614913650'>",
  "kid": "idpSig"
}
{
  "nbf": "<Der Token ist erst ab diesem Zeitpunkt gültig. Beispiel: '1614870450'>",
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1614870450'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "cnf": "<confirmation. Authenticated certificate of the client. For details see rfc7800. Beispiel: '{
                                                              "x5c": [
                                                                "MIIC+jCCAqCgAwIBAgIH..."
                                                              ],
                                                              "kid": "844508318621525",
                                                              "kty": "EC",
                                                              "crv": "BP-256",
                                                              "x": "dTXa6yPKCjIr9MbVFxeaLEu82xSCsRrfwcIrLpFqBCs=",
                                                              "y": "AJGsJ1cCyGEpCH0ss8JvD4OAHJS8IMm1/rM59jliS+1O"
                                                            }'>",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1614913650'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1614870450'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>"
}
```


## Token Request 

```
https://<FQDN Server>/<TOKEN_ENDPOINT>
Multiparts:
client_id=eRezeptApp
code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE0ODcwNTEwLCJjdHkiOiJKV1QifQ..bHIpUnczdCNKnXn4.5iSkdBQ_lUnmHSUoCxz7Ap51DZfeDKdNUTczQ1n0oBIEtIcp2jsK9iG0WXJewiMl9KED4MWx2-l7GZzXWIS-EjQ5VaNEiOyhWUcUdESf3CGVuzhVBL0RqB7On_adylrPQ4NHMqi7csf1WoPybCPioPDPaPKV1DJVcGcNskuRIam331JglGvdn8U2lYOBjGy-Jdna11OHCVy-PDvQlOUC6c1ycyIVmZD7O5bYt8lfSeR8Kak7ipX_dmRdCmgJ2D0u2eYfNkzCFUgkE_qrXxEIOUlNVerUQAG_b0wrnDLF94xlPdjr3d0ck4Xs2wioA_vwdoWNRVhrmx_XuydhFWYIBbCDAHd_R5mxJUT_y9kHa7PwtyuFvoYAQZlAZy9-I2nzsXk2N7cefDtq5R2PQKWOqkywTuzBTgSQkZchE-xzTYnSKafo0BKb7ThU-rlxhGJTLVDmoQW9lHj90kPSa4ve1HKZyrN7VrTk-2bbnlGHvyYxqR2Sb_v5WlZBEbCHtala96lCGQfTFi8A2VjxmdqrXl7IkhRWLrNbq-u5VFLgGq9hZaFGM56FUYSr9rOtyTEkVCfn_Iwtik5GWX0-RIEL7Ozgs7KXdVB6a3VHpRH_bUM_vVA9wEK3oSbUD64oHtb_TFGvN2259n5yRZ2J_GnAbO6enOOP_7nKwUniSnEKRjLzbgq9HdPSL1KHELJL4ZN10YwDOWHMnWa3a-v2dGqlXL_e13vItNK0cg7cABeqVk8WbY1vQB9bRpz2Or_idX3vpymUTlaMxN2sFFW7njM3VLr2W2T_Se8KjthWR8L5KDxHpE7wqia-HhOFhoS4LA5ctsqOfJevwpU3GRf2yhaWqaAJBBMWZrpqNBRLxbRR7J40uFvcEuxyVvOBRNuOW4R2SzdBOeMznhMEqS05YYdC0nFDj2M_dXPoV4vrUuvB0zaJDqBUk4567Z0vl3_mlg_Sq5fqiDOLUTOgR-YxZtJjXRVGcny9Q57Gc1fJhmIZoufvjjkYGMw5dM_y9puUzjofJFg1oSe4_3a-fx6HCz-7CEaNkaB2tFLfTKuUEQU8ntjEdr5Ew9_rCYuqw3GIxeFZYWOkAVUEgybZ_9JmQj8PzL8QnKq0DBwwtgEQbcFUSdipY37Ln1rx0m61HOMC4Cgtg9iJ3jXXQcQzC7ik51t-Pduz2KJ8vmAdS2g_3WLLCEM9HWAsF19fUeRVG6wWxVI5wpDP6zvQuA3XUBB49WZJ3kIpB9HsI6sA2ZE_g7Jt12X3kDfmLx_3ZtuKxng7cdzsAKeWFy3J3WbtgKj2UrzR6KNIUVVE2xS1Xt6ohV1NqVt52u2VyuVMnrdZnzyKz7orQtMYXCY.3nHlZSPdHeql8ok4yUCp0g
grant_type=authorization_code
key_verifier=eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJjdHkiOiJKV1QiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiRG5ZRHBSdGExanlmdU1yc1FfS2pFZVE2TER5UzVtbzhCZjRkbjZwbHFsUSIsInkiOiJMalhQem9YZzJOQ0x0ZlJ3dmY4QzFWSG9jeUhXUEdLYlpYTWwxenYyamM0IiwiY3J2IjoiQlAtMjU2In19.j_5EhuDQsiogrFSUla1iPUll3-bxs9TgS2lmgIkBMXCQa06kpxfKvQ.HThFMHsYSF8PYlm1.nLJWkzjJBiUFJ-QRGMlohaL_U7pnkdXZdStai7kCWaqYybEuw6PAu-qXYG3lzco1v-K8wohOF4cUW5izmO_GWEH9EZrmmo0AYTIxzpAmLLcDizOC9yrfwCr2thKjgrWnPxW7HZtwYzRBy8KINyQ6ZpdRdDwADQ1zdh8.8igoA-jGceMUj-2-TZqiYQ
redirect_uri=http://redirect.gematik.de/erezept

```

### Key verifier (Encryption Header):

```
{
  "alg": "ECDH-ES+A256KW",
  "enc": "A256GCM",
  "cty": "JWT",
  "epk": {
    "kty": "EC",
    "x": "DnYDpRta1jyfuMrsQ_KjEeQ6LDyS5mo8Bf4dn6plqlQ",
    "y": "LjXPzoXg2NCLtfRwvf8C1VHocyHWPGKbZXMl1zv2jc4",
    "crv": "BP-256"
  }
}
```


Key verifier (Body)


```
{
  "token_key": "NXVLR05VZmFqUEoxeERlUm9rNDZ3VjBCSHFLRWRLWmc=",
  "code_verifier": "lyLTvVoiraK4XdaQKHAniNNeyaMqXHE1jbMR3TC22h0"
}
```

## Token Response 

```
200
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Transfer-Encoding=chunked,
Date=<Zeitpunkt der Antwort. Beispiel 'Thu, 04 Mar 2021 15:07:30 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "expires_in": 300,
  "token_type": "Bearer",
  "id_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE0ODcwNzUwLCJjdHkiOiJKV1QifQ..vJowPl1SEmAk9BA4.gvu2MPBt4oQ-Kt1352K46JaxEH1UzPVG-qDUJXWxbYj6GbfVhOGlvS-vdiS1DouzbB7dtkxzcDDh9_376DRL_Ss9sdwwjBJvEnqDZnNbYSeq-9KWZsAlVLzj1wEW2_gmJ8J5gXwe7c7rENvBCuRW-E_9-z4gjoHVAkOYRbPp9NfspfTs6CrnowNJ1jeCdBt6i_s0AAmacnQhTvhdQEqup_pvDsz6croDcu-hZKiCoNkAjbVoo1d8nE8Uv1NKA7-VqZZPrxuWCVguAnRLTEJ0mUeQJi-4AmQmuyphhWitjXS-NX9a9hEcYqcNdsFg_5gZZpLx9h0HdF9u94utWW-hGikfa4fK8_BwY0wXHu12a5nELfh0A7l4tEwFLPkHMVNwSRWMlY5Eq1DC_SSrZ9TwDzZS5GKPcmU1Jj6MGZ-xzMmUYzYUCVwkWTcc7ClTnor3Qy2iq0_idE1dReD1su3tyyNYdzx438mZzlpc_l2pFiRZySHmPeNn4Ze49btlHetUuCUdAJ21tbAxoTsC-oB7YNPalaB5b9O-xfAVE-F4VJCx8SJmXg93srwG4zOquN8nFkaqz842MN5JFidQ8e-aWOtIxnWzdEMYJ_zdBYtWmYh83KAZ7aFdopVZCIopNU3fZ20mUkFxaPoF4gjJ8swIXjgnnlkWtP-RcU6KgSTbgtRNa4CIShw-DK-2UjlZqioHkdYMtftz1KW_rlcXf43O0Wml1ZTotP0-dS2en4-XkBVNR404YYY5b6RGKiHGHCNKA3nIqCFmU0sfxvO6SQ52ax6gFQkVZ-8T_T9mz6wP2vuCndjuSfPlbV53PCknsG0bwzcAlJo957trPD1SclSvM84fdG_Fi__uvRDk11MNEVwrow08_0u7LXQsEMOWln9dEVNFf2ondTOUtFc3zXpM9jy_jDwkaQEYbKCD_j-uoVBkiNNrURk_YBAKfpPI_Tx_cuj1v__qELW6WRO9T6AF_bHlmnm08H7tZ99amFUwkY-_QtcquRQCm9DXQaTI8Ykl4ELyLClaeCNUTmSDRoqyRwObogVXHfkeUA9kioN_7A_csNnVgy2GFuJiLZdKCde1ouCjZ9lljxCcrV1hyEMlPzt0N5fffSA8MUWaTF2Drco.A0jC6C27BfnCegbE3Zsbbw",
  "access_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE0ODcwNzUwLCJjdHkiOiJKV1QifQ..eshymLhXtAfdvgZi.EUbu2UlVlduNxw3qmEBbtU4EGjoi5VMk5M6K7pvgi8AK50Tx7lmFGWYENclONoJSR0TTLFA2MeKlqfvtZjeS2nIL_0BTw2is3s3dql23PYZ1BD4AcK_Ku1WGJ-ycr6s_4J1I_-F4XgZGDJcxUuPrInv4VT_t-BLwIWUt9LH-4WhfYlcplVCaoYPrG9NTPZZXDRiY1VNt7v0Gcfcju1WU7ukFVy3llXLpcgwjHgoG2fP7J0YIaEkRpPAkJrgPw5gK-_xgvEAYbrsi808rjyOc8NBLA9WPCjoTKk2Wpo7T-ljollW9UKTegaVgrIu_B4xe54lAdVdvhzLk2PtOkR9oVDo7pu6XPhaPZEH2GgjG8Q53DrKUhufy-XKp3fJXJt06NvupcYILj7O8d0L-uUOUiHhZM6jpmp6w504V-vkivaBU4VDH8vcW_L_hcbgp9KH09Jthey9zQjoWU6gdrNXEtUqm5s41x8Jfpo6Cog_wdKOt93Qb8tIkcqb-ac8M4oUe5vyLMzvgjP77NOVRyLP7V8ywpCQz_Zs-RrjQaENbjyUIAJ-EVtWZab31Pkkz2QypGnQA8eBi0pyvU463Mu1jNi2LOYDtuaoS8Xrlpd-LzDCmSk2211XdJu-OPEHNkNttk4hEfUxLqlQ3hVVrB_AbL9mGQlxChY-pVKQggr3sq_P6vF-qhJt5oU4hXkkbrtDcqI3oSGWG5ZER05ekasYuaABLUMwAPYAn6ZCM2j4_dulPHAFJEmxaMd2NoR-svPuILqjrhN8UDctA-bFozGmpihnxoMqqYlwBfVGCHVCx_R_oN5Vh5yCZ_7h8SOY2XGFSYsn5kqUnNhcVP-_9sfDk_-l0MzTAxJy8J1ZRqiiMR6uH3CY5e_EWqvGTMWM1SodiUW1LXdiI-1b7cgXjWn3D_dH3oayhGgpFzCwiSAA1i2K5VlyImQu6QHcdK_R-dOKpv22YOMt4Zxvp4I7U7SqyqlMTux-JBnjqRXNGI3I2hy5G7oCSvRxJqKOPoqK-BdMypIL1hVGh4hPl5l1hCAuXUKnkGM94RtI5Su-WcfsBliCBxbZ_6rSU1nIY6PAmChrNYb2-o1MtJUim4TnqUg1Epg9vEP3n4DMTf2N1ZHFswTMkYFdXuxdp-Ph4.tKlfrYochMvzs6sRfakf0w"
}
```


### Access Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1614870750'>",
  "cty": "JWT"
}
```


### Access Token (Decrypted):

```
{
  "alg": "BP256R1",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1614870750'>",
  "typ": "at+JWT",
  "kid": "idpSig"
}
{
  "sub": "<subject. Base64(sha256(audClaim + idNummerClaim + serverSubjectSalt)). Beispiel: 'qDAmiQOl5_rJ5-ok48lbjSs6QH9oya7VuxUJ-_E1HCw'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "amr": "["mfa", "sc", "pin"]",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "client_id": "eRezeptApp",
  "aud": "https://erp.telematik.de/login",
  "acr": "gematik-ehealth-loa-high",
  "azp": "eRezeptApp",
  "scope": "e-rezept openid",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1614870450'>",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1614870750'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1614870450'>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '4ab39f2042a7c020'>"
}
```


### ID Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1614870750'>",
  "cty": "JWT"
}
```


### ID Token (Decrypted):

```
{
  "alg": "BP256R1",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1614870750'>",
  "typ": "JWT",
  "kid": "idpSig"
}
{
  "at_hash": "<Erste 16 Bytes des Hash des Authentication Tokens Base64(subarray(Sha256(authentication_token), 0, 16)). Beispiel: 'plLwXSFMOmrI8dWp5hE9kg'>",
  "sub": "<subject. Base64(sha256(audClaim + idNummerClaim + serverSubjectSalt)). Beispiel: 'qDAmiQOl5_rJ5-ok48lbjSs6QH9oya7VuxUJ-_E1HCw'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "amr": "["mfa", "sc", "pin"]",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'Ft344624J2YoCnve0DmK'>",
  "aud": "eRezeptApp",
  "acr": "gematik-ehealth-loa-high",
  "azp": "eRezeptApp",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1614870450'>",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1614870750'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1614870450'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '47cc7cf4c96a9e4f'>"
}
```


# SSO Flow 
## Authorization Request 

```
https://<FQDN Server>/<AUTHORIZATION_ENDPOINT>
    ?client_id=eRezeptApp
    &response_type=code
    &redirect_uri=http://redirect.gematik.de/erezept
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'FdPMbjyvsPDFEJcVA8hA'>
    &code_challenge=<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: k7WEwUKmlfJ9eKQMjlhloroivAjOWFcCBTc2RE2nCAM>
    &code_challenge_method=S256
    &scope=e-rezept+openid
    &nonce=<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'GG03sX2yTAvuS13ye4PF'>

```

## Authorization Response 

```
200
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Transfer-Encoding=chunked,
Date=<Zeitpunkt der Antwort. Beispiel 'Thu, 04 Mar 2021 15:07:30 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "challenge": {
    "rawString": "eyJhbGciOiJCUDI1NlIxIiwiZXhwIjoxNjE0ODcwNjMwLCJ0eXAiOiJKV1QiLCJraWQiOiJpZHBTaWcifQ.eyJpc3MiOiJodHRwczovL2lkcC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJzbmMiOiI0cjZQWmt5QWpyd1dXUTBlNmZkOGhpSm9TazhtQVpBWkJhbndFbjJKaWxZPSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJ0b2tlbl90eXBlIjoiY2hhbGxlbmdlIiwibm9uY2UiOiJHRzAzc1gyeVRBdnVTMTN5ZTRQRiIsImNsaWVudF9pZCI6ImVSZXplcHRBcHAiLCJzY29wZSI6ImUtcmV6ZXB0IG9wZW5pZCIsInN0YXRlIjoiRmRQTWJqeXZzUERGRUpjVkE4aEEiLCJyZWRpcmVjdF91cmkiOiJodHRwOi8vcmVkaXJlY3QuZ2VtYXRpay5kZS9lcmV6ZXB0IiwiZXhwIjoxNjE0ODcwNjMwLCJpYXQiOjE2MTQ4NzA0NTAsImNvZGVfY2hhbGxlbmdlIjoiazdXRXdVS21sZko5ZUtRTWpsaGxvcm9pdkFqT1dGY0NCVGMyUkUybkNBTSIsImp0aSI6IjNiNTlhMzYzNjA4MzFiYWMifQ.N564TZQCt81dkFHiGkeECahMzj8OWah9R83MASzQVnZKodjwrZefk4ZqwEJmU4sZmUiEXuuNWvn706r-CELIGg"
  },
  "userConsent": {
    "requestedScopes": {
      "e-rezept": "Zugriff auf die E-Rezept-Funktionalität.",
      "openid": "Zugriff auf den ID-Token."
    },
    "requestedClaims": {
      "organizationName": "Zustimmung zur Verarbeitung der Organisationszugehörigkeit",
      "professionOID": "Zustimmung zur Verarbeitung der Rolle",
      "idNummer": "Zustimmung zur Verarbeitung der Id (z.B. Krankenversichertennummer, Telematik-Id)",
      "given_name": "Zustimmung zur Verarbeitung des Vornamens",
      "family_name": "Zustimmung zur Verarbeitung des Nachnamens"
    }
  }
}
```


### Challenge Token:

```
{
  "alg": "BP256R1",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1614870630'>",
  "typ": "JWT",
  "kid": "idpSig"
}
{
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: '4r6PZkyAjrwWWQ0e6fd8hiJoSk8mAZAZBanwEn2JilY='>",
  "code_challenge_method": "S256",
  "token_type": "challenge",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'GG03sX2yTAvuS13ye4PF'>",
  "client_id": "eRezeptApp",
  "scope": "e-rezept openid",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'FdPMbjyvsPDFEJcVA8hA'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1614870630'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1614870450'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: k7WEwUKmlfJ9eKQMjlhloroivAjOWFcCBTc2RE2nCAM>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '3b59a36360831bac'>"
}
```


## Authentication Request 

```
https://<FQDN Server>/<SSO_ENDPOINT>
Multiparts:
ssotoken=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE0OTEzNjUwLCJjdHkiOiJKV1QifQ..hTTZs5ciwOhCH9h5.nt7LWyF68hTuXKv1BQrW3c1rRJzSEPyI9p3nbEJgDalEdix37MMXrY5xyrK2xGbHV_6AdKHPSPBIaniqan5mRkxiY46Q3_8AiH9exDESDLX1OwQSA9PWHcHWxg7ukDCJkN0F1NRwir553lVryZIJpGDwklKa0hlHyNAqR1XNzgvSLMN8P9YYtZTFcFiAqPRAMVSrrh6Qu3pslHq3eUdO5lC8lHJC6UnjsJJirD-sIhEUhdWhVMVdJWV2AdbDK_4WryiWxwyinWCpymQR7_p5J6cn0DyVLTM07x2XLhSY2ehaA83hdUpxJHxCG6VjFqlB2DCpNsR22nr1shuhGSMPxCYMHGgw-kMvSumjrlfKlcvF2ms8zGwskf6o0GQqgOnHllYxA3fRvigMC3tT8RxKVzG3pbelpn3dWg4FS0Z41JsSxquRvAVDnA4-M2k9H-7ncUqV_4iUDm71NWmz7urA71hbB0sDlbk-FH8KPWCHT0yIlSmhYhewhU1Alexw9KYTVml3VK4_mVct403rV1b8b2ZnCT8owQ28lxrMbN18Hr6DJch14p--_sce2MZC2yf2wWtxxcb8wxtwMOMZ3BuNYie7bvxMpaDA-NJkcXrQU563G4RfxQoZ7I_TGB_M-0rrog9k62Syuee1UIbRxVOMOmcHlfYu6402wITIWja151cQiB1ZNFioSU8s7KzYsoHg2mHzr02m2oUDmdU4vWiSXjuPPIjf1Jf_-_tru0k1IymWlMHurJzfjiQs3H0YG99n_6wgK-8D9hahHfgskryLbfLKUBma23uXIj7_mgZV3aCxjP14CBBHHfZaPA6s4dmWtiv5KwYH3oTBC_x17IOqr4Kg2waFu7f600H9JruwJvcoTIvvf-2bjIxfAkAGJjnbpiDHg2GmbZTXfpBpGt-pqA0w1iHcAQp4rfEe0LdHbVfZPrOCkM-wW_LOO8WgklM_SrQw_P8lzh6-41AYYFxPeaczEcWk8kTccfF3rc7n5B8hoMIR4dkl3bD9brmjLRTCKnR7yTXRqEUlX1QWfpxVXwkF5hJrPm_mD5UqK2c4JiZRHDEhQT1empEGBIEIDygCH04dww0WG9MMdBKcZmhKZy4lLf4_Yh5qUbUTDf1def5QYzQ4Il6I5CRvvlT0S7ncBBxp4czlgn1yxjWqWqBMhl7TV8yFowtbpJWMAVGal0H9IsGrygN8-1hDHx5M9rJpkfTja7VCdUiRYYhQHKCULNCXipYfhYilsytE373Vn8AOYKzFY73aNc9AamzSXZP3P7HG45X1KnT8ziYVz32VYW3I1cIed7dwf-EpJ35d9v6dZTpzgjbov15xSgpvlOtEo7eqSp6E35-IttBbOx8d1iAqJ7k7d8pT1iVurVa_KMdYJuIs3o4PgkIrBZFNmaJDDNggQhecwWae9rvhqUa0OP0NHNe5sQbmNY-dvcHJu1ueDQ9wHowt8zVJ5S35NzizgW_0XTOsQYHwvFLB6Jrqpqkgqk9GzdvLR9U0itgxk8t5Nqax3t8kJxYXm5PuFEkeI2x-8QAmhLspTDIw1bMvL_lb_EVHSEQCtAivfd1f7Rqx-8A3GDxuZcKvRpbzNuEyamEa_7y3komNdq1yVHabVJyEyJwDd_9Y6Adsq0U1nMCJYrxeNqLslhsEDPEVrg-EnaWQZ1zNTbZVcfCVJ-mqjmfdeAG_zhTOOFtoNXRGNBvoW38wk2SDTVPil4TTxf46gT9Zk9nADfze99qlUCp-1Wiw9jiyb0NdoylPVIxJSyACpGxwza5w32TuRzbUFI18gJYpze9C-d3uzp2FyORxb2o-nQlrrPi1SQo4LQ_Oj5u62qh3Oji2OQChMG6FBiudNV75iYWu5OMPoQX40yTrRUA9TwXoY6r6QxMqQZf06a3k-GjqvQy_fmyjw8Ja815T7gkI9prHUQppVqTDVLUyKg9zu_ouCRhGs_jV5co3IfbGy5khSiZS5w4tpJUCBqPKQbnayUvXUgz_JX71uzm7YwDwoknsUU7bWx1LtLchmKPMelzUMEAkOfu6RIRHXzcRJTLf28vQFM78UMx4SE4D24m9nsN9sUkZ33oasx11yUvEchNNse24O0K3Ql7Hp0k6wqW5Iponx7Bbe8CrITk8FmLOeGvjXRphSa6QD80wX5bgDQr150EsozjbfbveQHAdMYzWpJ-5ZBOQqNp7AS9ltPQLBC1cNp88kBXauW4ZKdKL_PxfMpmsT3za0LZx5BQKwRPOdJ8FVSs_R7gWDNa6VF6O-LOvWeYmQ4zCrtla5t9a6ONML_8hIaZihpdc4nJSybxQOEgAx9ALWc33eucJKdTCInn1ZDb_2jM4tOZ1dytOWV5DuiAto6kgBbuTy1inCuLJWJRLU8AwUTbGNfUuKjFRJNlJKNDn2DsS3HEb3u_UfdxTqCGZBvbtt9Dkt8uO66aTEGsPlgeBuZjWdIZNiCuWyeiFhbWfTBmmdQB1LpZccq0bauGWKacFPCpBlbeYoiCKLgtviYzgiK823kKuS-6v2oCoMhjGzWaGnMXfyFSW-5AHSiuc5SrN4Ukopp0eOs_QXe5QXqzqpgxaRG8m4S6g55eUCpgqfFwkQlabUehM6ikjEl-DLTAHdRHwEsFhRl2X027guX2ES7XUr6HObTUlF6mPsCipUBkJE9PBiqUUkepKS_c8NG5AlDwr66ZKerfTztkzPp_QdLGJhdNOEpRS1hG6p2h2OeLwoJv1LdBO4IZSHU89Lu5ipTzXHFccEdWTOwXK7Gj96GTTc2YoQsm9hQeco6HmoIb7LA0WYIaoWNEQ43BJiFkEjRvoSlJDmVz_bNOGpj9lhuTK5pGdUTCmbtU.bMme2nNMaP9z3W4x4rQDAQ
unsigned_challenge=eyJhbGciOiJCUDI1NlIxIiwiZXhwIjoxNjE0ODcwNjMwLCJ0eXAiOiJKV1QiLCJraWQiOiJpZHBTaWcifQ.eyJpc3MiOiJodHRwczovL2lkcC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJzbmMiOiI0cjZQWmt5QWpyd1dXUTBlNmZkOGhpSm9TazhtQVpBWkJhbndFbjJKaWxZPSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJ0b2tlbl90eXBlIjoiY2hhbGxlbmdlIiwibm9uY2UiOiJHRzAzc1gyeVRBdnVTMTN5ZTRQRiIsImNsaWVudF9pZCI6ImVSZXplcHRBcHAiLCJzY29wZSI6ImUtcmV6ZXB0IG9wZW5pZCIsInN0YXRlIjoiRmRQTWJqeXZzUERGRUpjVkE4aEEiLCJyZWRpcmVjdF91cmkiOiJodHRwOi8vcmVkaXJlY3QuZ2VtYXRpay5kZS9lcmV6ZXB0IiwiZXhwIjoxNjE0ODcwNjMwLCJpYXQiOjE2MTQ4NzA0NTAsImNvZGVfY2hhbGxlbmdlIjoiazdXRXdVS21sZko5ZUtRTWpsaGxvcm9pdkFqT1dGY0NCVGMyUkUybkNBTSIsImp0aSI6IjNiNTlhMzYzNjA4MzFiYWMifQ.N564TZQCt81dkFHiGkeECahMzj8OWah9R83MASzQVnZKodjwrZefk4ZqwEJmU4sZmUiEXuuNWvn706r-CELIGg

```

### SSO Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1614913650'>",
  "cty": "JWT"
}
```


### SSO Token (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1614913650'>",
  "kid": "idpSig"
}
{
  "nbf": "<Der Token ist erst ab diesem Zeitpunkt gültig. Beispiel: '1614870450'>",
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1614870450'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "cnf": "<confirmation. Authenticated certificate of the client. For details see rfc7800. Beispiel: '{
                                                              "x5c": [
                                                                "MIIC+jCCAqCgAwIBAgIH..."
                                                              ],
                                                              "kid": "844508318621525",
                                                              "kty": "EC",
                                                              "crv": "BP-256",
                                                              "x": "dTXa6yPKCjIr9MbVFxeaLEu82xSCsRrfwcIrLpFqBCs=",
                                                              "y": "AJGsJ1cCyGEpCH0ss8JvD4OAHJS8IMm1/rM59jliS+1O"
                                                            }'>",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1614913650'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1614870450'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>"
}
```


### Unsigned Challenge:

```
{
  "alg": "BP256R1",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1614870630'>",
  "typ": "JWT",
  "kid": "idpSig"
}
{
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: '4r6PZkyAjrwWWQ0e6fd8hiJoSk8mAZAZBanwEn2JilY='>",
  "code_challenge_method": "S256",
  "token_type": "challenge",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'GG03sX2yTAvuS13ye4PF'>",
  "client_id": "eRezeptApp",
  "scope": "e-rezept openid",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'FdPMbjyvsPDFEJcVA8hA'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1614870630'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1614870450'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: k7WEwUKmlfJ9eKQMjlhloroivAjOWFcCBTc2RE2nCAM>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '3b59a36360831bac'>"
}
```


## Authentication Response 

```
302
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Location=https://<FQDN Server>//erezept/token
    ?code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE0ODc0MDUwLCJjdHkiOiJKV1QifQ..uN9xYQO1lcwe5CzB.ALnLtdeSmBKVvhCuIAPhVnjdNmlKFSB49zobJUUzeQjoChtG6ZvKzPZXDJ5HFfptkvofDytwuT1tzj1W7CWie3MLzt-RzbYlyxditOZxCmko-PEg8D_D64fLdE457z-IwicNmCJ9bzxYValLXBUS7Oe_qzfFt9jozbQ44rZXrrT51DwAg9AmJeUFwHx7zxvdkwV9rdoYHknuz58RRpA1NDdY1ChMaGbfVhErmnZVMANapRagBWehUeJu0s9J_h-lox2GP4ImllEB7SGAI7Uu1ChlU1UjpR299GlFDG7pCJDOBjujcukjO7-Kpq6GghTKzTDgjClbWal42H_3ZvJ8kN3hxgoXGaD4eHwoQJoAc2Za5soLmKNOfpushvU2-RaCBfUK5GOKxxPRDYVSuGayenuwBGdLb4AiUC5b0kGH4eqew24RUGi2P_HFRh9HGthrYBCcTPg5drWvq1Cu2KLrgLAz8i2PDgc2E8uOfvBhB9xZExXkP3is3uUqb4ouA79pKcOn0a2xkmp24-9CqkplMnOBOk8gk1Ti3MG6VpHreHOKDr1B3ksbkpZ5vtLNjy4IIR562TZj7r04mYQS_5MwYwCnL5kFIt4Gr3Wl1srXe5o3zKv73j-3wASfTg7Ezc6Z05WZ84l4WYirSydKCjAVf4WkEiLL0omS9bsg_9Bnqv5_bW_yb9cqeYlSKlth1p73VvmMRENT7WIjEHJyCj8e0_M3Genycja0zZz4AiuVM-iPu3VMwUcUMZX8XykyiBtI-fvMUfxAy3Hsvv30jJXxXyph46VJSUCvFIpqS9hWagHYzYCrhoJXDUyfed8-lPpEBdesI-lWukUGcVOiPj60tylTPJQAgqJwqo6PvcXeLzOdu585wmS9YaFp51yYyho0WcoMu24LQ3yA2qrqMD_gE2_OWEn0FuCBkublY4XzyoeAP0pqqdqEs4YenQtIRb-A2M6SiemkpV61UTORVbb9CfmtEaXhsy5dDZLxfG4zLJOd1opHtcpXFeIcxNtlmVXFj-eczHRMGrCuoWerx3-8rsVpQrVqAPOz8dbQdYSrkxA_AUecYlbqtbFvBlZzfYM2Ua3CtDRn5ndOLiCIUh6XBb2cyHPND_MFxnZZMEI3eyWdS2qFG3iKEpbqip7_YbHu6xUTVGvXHDVdPsdcSf37ipwTBUK7Css5TOLN1frp2UDX8T0XOL0pMzUGqbsdj3ZgXcRR-yTga5RvhfmpFEWfIFgKO_dklyPfFn-quxrUTUO7vUaQiTUzCLsFCXjJAr--EZwW8KzQp9M.v_rv11p0ZYGKemuBWAmj8w
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'FdPMbjyvsPDFEJcVA8hA'>,
Content-Length=0,
Date=<Zeitpunkt der Antwort. Beispiel 'Thu, 04 Mar 2021 15:07:30 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


### Authorization Code (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 1 Stunden. Beispiel: '1614874050'>",
  "cty": "JWT"
}
```


### Authorization Code (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "exp": "<Gültigkeit des Tokens von 1 Stunden. Beispiel: '1614874050'>",
  "kid": "idpSig"
}
{
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'nyM5aJjegMX3qhqfBgRV'>",
  "code_challenge_method": "S256",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "token_type": "code",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'GG03sX2yTAvuS13ye4PF'>",
  "client_id": "eRezeptApp",
  "scope": "e-rezept openid",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1614870450'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'FdPMbjyvsPDFEJcVA8hA'>",
  "exp": "<Gültigkeit des Tokens von 1 Stunden. Beispiel: '1614874050'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: k7WEwUKmlfJ9eKQMjlhloroivAjOWFcCBTc2RE2nCAM>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: 'fb2759f4cdad8b6f'>"
}
```


## Token Request 

```
https://<FQDN Server>/<TOKEN_ENDPOINT>
Multiparts:
client_id=eRezeptApp
code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE0ODc0MDUwLCJjdHkiOiJKV1QifQ..uN9xYQO1lcwe5CzB.ALnLtdeSmBKVvhCuIAPhVnjdNmlKFSB49zobJUUzeQjoChtG6ZvKzPZXDJ5HFfptkvofDytwuT1tzj1W7CWie3MLzt-RzbYlyxditOZxCmko-PEg8D_D64fLdE457z-IwicNmCJ9bzxYValLXBUS7Oe_qzfFt9jozbQ44rZXrrT51DwAg9AmJeUFwHx7zxvdkwV9rdoYHknuz58RRpA1NDdY1ChMaGbfVhErmnZVMANapRagBWehUeJu0s9J_h-lox2GP4ImllEB7SGAI7Uu1ChlU1UjpR299GlFDG7pCJDOBjujcukjO7-Kpq6GghTKzTDgjClbWal42H_3ZvJ8kN3hxgoXGaD4eHwoQJoAc2Za5soLmKNOfpushvU2-RaCBfUK5GOKxxPRDYVSuGayenuwBGdLb4AiUC5b0kGH4eqew24RUGi2P_HFRh9HGthrYBCcTPg5drWvq1Cu2KLrgLAz8i2PDgc2E8uOfvBhB9xZExXkP3is3uUqb4ouA79pKcOn0a2xkmp24-9CqkplMnOBOk8gk1Ti3MG6VpHreHOKDr1B3ksbkpZ5vtLNjy4IIR562TZj7r04mYQS_5MwYwCnL5kFIt4Gr3Wl1srXe5o3zKv73j-3wASfTg7Ezc6Z05WZ84l4WYirSydKCjAVf4WkEiLL0omS9bsg_9Bnqv5_bW_yb9cqeYlSKlth1p73VvmMRENT7WIjEHJyCj8e0_M3Genycja0zZz4AiuVM-iPu3VMwUcUMZX8XykyiBtI-fvMUfxAy3Hsvv30jJXxXyph46VJSUCvFIpqS9hWagHYzYCrhoJXDUyfed8-lPpEBdesI-lWukUGcVOiPj60tylTPJQAgqJwqo6PvcXeLzOdu585wmS9YaFp51yYyho0WcoMu24LQ3yA2qrqMD_gE2_OWEn0FuCBkublY4XzyoeAP0pqqdqEs4YenQtIRb-A2M6SiemkpV61UTORVbb9CfmtEaXhsy5dDZLxfG4zLJOd1opHtcpXFeIcxNtlmVXFj-eczHRMGrCuoWerx3-8rsVpQrVqAPOz8dbQdYSrkxA_AUecYlbqtbFvBlZzfYM2Ua3CtDRn5ndOLiCIUh6XBb2cyHPND_MFxnZZMEI3eyWdS2qFG3iKEpbqip7_YbHu6xUTVGvXHDVdPsdcSf37ipwTBUK7Css5TOLN1frp2UDX8T0XOL0pMzUGqbsdj3ZgXcRR-yTga5RvhfmpFEWfIFgKO_dklyPfFn-quxrUTUO7vUaQiTUzCLsFCXjJAr--EZwW8KzQp9M.v_rv11p0ZYGKemuBWAmj8w
grant_type=authorization_code
key_verifier=eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJjdHkiOiJKV1QiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiVDlDRHEyREtXRVBqbFZQelZ3cjZDVjZNOE91QjVvODFSQ25mQVZMZkplQSIsInkiOiJjdGVjQXpXclZmZksydzBkazlwaDRsZ1gyNnRub05ycmdzRDlTOW5CSkJFIiwiY3J2IjoiQlAtMjU2In19.F_fMhK5rqnReg_sO5A-J9JIzGn6di9HYo9I02Pn_udCL1p4Gcg6yBg.pot_Qz52nO-GnhZf.RkclvRwQOoktDXpJyTeR1cYv7wQoSFWOMvX604n-1OrEBx-Ot5vRIEr3SOxEUEswmlQ9nuciz880m-2Yf2C5n_54TvtPl37hJqgaBWj50k4euDmle58dBRgqmQX_pROFY-RbBhSin5aY5eRO2rLLHkU8aRjILavKOCY.evBV7Yze0ErsvS79COB5vw
redirect_uri=http://redirect.gematik.de/erezept

```

### Key verifier (Encryption Header):

```
{
  "alg": "ECDH-ES+A256KW",
  "enc": "A256GCM",
  "cty": "JWT",
  "epk": {
    "kty": "EC",
    "x": "T9CDq2DKWEPjlVPzVwr6CV6M8OuB5o81RCnfAVLfJeA",
    "y": "ctecAzWrVffK2w0dk9ph4lgX26tnoNrrgsD9S9nBJBE",
    "crv": "BP-256"
  }
}
```


Key verifier (Body)


```
{
  "token_key": "ZjVPaERPSVZRTzlLUGt0NXNLdEw5dFFGS1AyeDRoMno=",
  "code_verifier": "2ky-FCkhBPTON9hg76mgAHwx0VZjTS3vSQPIs7Irdq8"
}
```

## Token Response 

```
200
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Transfer-Encoding=chunked,
Date=<Zeitpunkt der Antwort. Beispiel 'Thu, 04 Mar 2021 15:07:30 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "expires_in": 300,
  "token_type": "Bearer",
  "id_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE0ODcwNzUwLCJjdHkiOiJKV1QifQ..NdtBSaM9J9AM_Z5F.N0MS_ZU8ripqV1X_KoDuOy-OWyadk8Y73O_3BgDaYacuq6ueNHu9zGo4OcrVogv0FBuXYUE1tveTpel2PAWNAEsA7quFoAIw2svE1gFrH_5c0CkV0mqyxaxR8uxWljtRNF1wgUjU5xnZexrjZyfdh2nx4IfoTqgjXhDZ9dHlyh3FjJiOmFaCQtbXWvhF24nKViaW8w_YWfgmfTLa9MsWsgxfYZx9WUnPjTX6O5kF7-DY3nhLCbDsHgJj7Zk3I7hBIaypk05v9CC2J63Ir0MEiems8QR0hYLSSPWqo2G9SKhBzGmTEABS-wYubz6lZfbaKGP3FACqFS64Z_-DY4Yx2MjbrVHu_S_FRT1GiLs3QW9t-KRijA88vcYaLoQmKQ4Kft0iUsivT_bbCzcWiVHSCsIaXGqakJW72bCNuJvPuGTCtM1N5O9vN98zbEz4koBlRC9exK7XmmdnUBntI-GyrFQ8wGfKwQR9e-Az7ikBZWoovF660paALGlBZR2P9zuI7H4oR6odSm7Vbp0Zagc-3TC1cbMsZIhE8W5H_MU4VTH6qkqvRNCjJynACB99ZbmFYW2YNCIRjlPP1IKg9UCHUW7LTc_S2nKNjg3MMiekDnd6q4avv_Hvi7pAg_CQ9TwUeK2OpS93C57ZzJXehfKtc7dFdA879hr-6TOirVAXHFC3KfI8_DWiCJ4APGMn1p2RNCeuVHrj_Ac3NDB3TLcCXfBY3B6mJzww7W6FGYfnf_sjPs3nLEjuFRXRnBd31lKgTlHzOQcb8BiHFjXdEZFJ5o1pdM67qA8KLt88MkeNtk7GtFYfVcWuTxjjZ5r63NujEXD8ptEGYujv_mjz34OBh59Kz-ghtu9_RLG8ftQ66nWkKhtUmJwCoN7Ji2tXUSt-nQGDqbWPS9mKdoYwAdp1BLTDEtOh9GhlViZrEmS-ETcGZvZHVDLMne8PvsZsAkh5akFWJ1Pdv9_OoNFMFnOmy5htJihzEeMyMWPRYM84jUb2QpxuQ3Sv3GbkQScZh2t8rDgEk1tyFsGPqfjDyjIzuMP5gF6sLwStZIracOLgvhPTsm8PG5jXI6qLMjx4Lz0DDCPnbxb-vkf4asHC5pwe8GhB177ZOMjIS8KoclroCjs.w63RB47_QEFmXa-3Ej-vCw",
  "access_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE0ODcwNzUwLCJjdHkiOiJKV1QifQ..0aN7Gi052BPovFT4.6Qd8O-WTsnjHaY7vwMQs78-hqpitEQXTZdhOQSZrlm4zuUPEigRfzNSdBDFlkruHyQ96aJhGz9tcIK-7tyTc5aB2kisrwfO1KmPDBsevJZUNWVxYP9BVkbDILiv_862jll6oowJr8ANEp4L_rZSGg6f8J62O07gTIhOun5lyzlmSA-9RkVJfarjloZjhMNeAK8p7tdGnthdQcLxvglzq7Snf6W6YmzzmFwLKR_5dqfjL2uiV1f9W6ojyXz6rA3UyxBO3BNXU3o-0Pq598A20VstvtpnY6BA0ej3rw5Pb9RFIwTL8LFuxJ-Nm4Mll0N4d2mNv13p2WN4LpP-kIVgkb1P3Pu_1LXZTqJmOuOxzjJ9myjUlWUe4d9fpsnfVWnAGIYtGvaWdlpKjKRImwboIx38bmdfNu2wRdmFghn-NLMcjMjp2n2V-d7ruKHH5goVyWMGmHPO8hwLLEPCXejYCE70Y2KhVSO-9Wj4bZcLnPobLtoF5yjoWHBbvvfr30NB_sQPgSbCAhZp5JFgbiTJ4VDdNeyKQkBD9H5Hhbm-16Xiv3KuJapCJcT6S7LNVJxY02SuF532UaL-Jg-qjEcklrBGgM9yQuDsndvX3RfAdQSVCxBQlEDpUpWRF3ea9EaKT4dQjodULsJScTuegj9H8mR_BjUrHMsQxf-W2H3dsJpbg5jpEUwR_TuZcbMcMmJKcW-_ZowDjDcXgrHRMG2Wdg0KHFcgUQ6bHIg-3u5ZvWaVxus2YknnRBqWM6rYOdVA1NqgPtaZW7S3FabxmI4BjwWQHkpYQp_c44CNpzDVOxmmS3naOQ9EQT2woH4Ky4nhxwtGX6-2k63pBggYNjMC46e3grNuC7-I6HAyeydkM-qYj3QkEw3VeZzO9J5kOG86wFmV2aO25DdbDZrRy9AxsOEVFcBbeSHyp30KKwGG76arT0EnNDs3RBE2lf5bLfjim6pbESUs_uLPLfrOsD6HYRb5WzuWhXwIY7v96D25W8bUlipKiiqiWWHPvvcn7Oz3a5Y6MJJPP2ROr1fahxSJYD28Y0S40GF4QcIqcRnzRSFR3WtjOq17dnD-_a30ya5OVZbEcPWloRsdln4mIYx8tVG_ej7229IWpdQas2zFDnDHtXTFHkI7pwDXb.qpMeHSYU5iIw3M4pkcJgvw"
}
```


### Access Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1614870750'>",
  "cty": "JWT"
}
```


### Access Token (Decrypted):

```
{
  "alg": "BP256R1",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1614870750'>",
  "typ": "at+JWT",
  "kid": "idpSig"
}
{
  "sub": "<subject. Base64(sha256(audClaim + idNummerClaim + serverSubjectSalt)). Beispiel: 'qDAmiQOl5_rJ5-ok48lbjSs6QH9oya7VuxUJ-_E1HCw'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "amr": "["mfa", "sc", "pin"]",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "client_id": "eRezeptApp",
  "aud": "https://erp.telematik.de/login",
  "acr": "gematik-ehealth-loa-high",
  "azp": "eRezeptApp",
  "scope": "e-rezept openid",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1614870450'>",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1614870750'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1614870450'>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '8089fecf940bab0e'>"
}
```


### ID Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1614870750'>",
  "cty": "JWT"
}
```


### ID Token (Decrypted):

```
{
  "alg": "BP256R1",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1614870750'>",
  "typ": "JWT",
  "kid": "idpSig"
}
{
  "at_hash": "<Erste 16 Bytes des Hash des Authentication Tokens Base64(subarray(Sha256(authentication_token), 0, 16)). Beispiel: '8irxoqSpLNa7RQ-Ow3LQ5w'>",
  "sub": "<subject. Base64(sha256(audClaim + idNummerClaim + serverSubjectSalt)). Beispiel: 'qDAmiQOl5_rJ5-ok48lbjSs6QH9oya7VuxUJ-_E1HCw'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "amr": "["mfa", "sc", "pin"]",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'GG03sX2yTAvuS13ye4PF'>",
  "aud": "eRezeptApp",
  "acr": "gematik-ehealth-loa-high",
  "azp": "eRezeptApp",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1614870450'>",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1614870750'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1614870450'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '18bbe01b6d0cecb7'>"
}
```


# Discovery Document 
## http://localhost:54987/discoveryDocument 

```
200
Cache-Control=max-age=300,
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Content-Length=2665,
Date=<Zeitpunkt der Antwort. Beispiel 'Thu, 04 Mar 2021 15:07:30 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "alg": "BP256R1",
  "kid": "discSig",
  "x5c": "<Enthält das verwendete Signer-Zertifikat. Beispiel: '[
                                                              "MIICsTCCAligAwIBAgIH..."
                                                            ]'>"
}
{
  "authorization_endpoint": "<URL des Authorization Endpunkts.>",
  "alternative_authorization_endpoint": "http://localhost:54987/alt_response",
  "sso_endpoint": "<URL des Authorization Endpunkts.>",
  "pairing_endpoint": "http://localhost:54987/pairing",
  "token_endpoint": "<URL des Authorization Endpunkts.>",
  "uri_disc": "<URL des Discovery-Dokuments>",
  "issuer": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "jwks_uri": "<URL einer JWKS-Struktur mit allen vom Server verwendeten Schlüsseln>",
  "exp": "<Gültigkeit des Tokens von PT24H. Beispiel: '1614956850'>",
  "nbf": "<Der Token ist erst ab diesem Zeitpunkt gültig. Beispiel: '1614870450'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1614870450'>",
  "uri_puk_idp_enc": "http://localhost:54987/idpEnc/jwks.json",
  "uri_puk_idp_sig": "http://localhost:54987/ipdSig/jwks.json",
  "subject_types_supported": [
    "pairwise"
  ],
  "id_token_signing_alg_values_supported": [
    "BP256R1"
  ],
  "response_types_supported": [
    "code"
  ],
  "scopes_supported": [
    "openid",
    "e-rezept"
  ],
  "response_modes_supported": [
    "query"
  ],
  "grant_types_supported": [
    "authorization_code"
  ],
  "acr_values_supported": [
    "urn:eidas:loa:high"
  ],
  "token_endpoint_auth_methods_supported": [
    "none"
  ]
}
```


# JWKS 
## http://localhost:54987/jwks 

```
200
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Transfer-Encoding=chunked,
Date=<Zeitpunkt der Antwort. Beispiel 'Thu, 04 Mar 2021 15:07:30 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "keys": [
    {
      "x5c": [
        "MIICsTCCAligAwIBAgIHA61I5ACUjTAKBggqhkjOPQQDAjCBhDELMAkGA1UEBhMCREUxHzAdBgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxMjAwBgNVBAsMKUtvbXBvbmVudGVuLUNBIGRlciBUZWxlbWF0aWtpbmZyYXN0cnVrdHVyMSAwHgYDVQQDDBdHRU0uS09NUC1DQTEwIFRFU1QtT05MWTAeFw0yMDA4MDQwMDAwMDBaFw0yNTA4MDQyMzU5NTlaMEkxCzAJBgNVBAYTAkRFMSYwJAYDVQQKDB1nZW1hdGlrIFRFU1QtT05MWSAtIE5PVC1WQUxJRDESMBAGA1UEAwwJSURQIFNpZyAxMFowFAYHKoZIzj0CAQYJKyQDAwIIAQEHA0IABJZQrG1NWxIB3kz/6Z2zojlkJqN3vJXZ3EZnJ6JXTXw5ZDFZ5XjwWmtgfomv3VOV7qzI5ycUSJysMWDEu3mqRcajge0wgeowHQYDVR0OBBYEFJ8DVLAZWT+BlojTD4MT/Na+ES8YMDgGCCsGAQUFBwEBBCwwKjAoBggrBgEFBQcwAYYcaHR0cDovL2VoY2EuZ2VtYXRpay5kZS9vY3NwLzAMBgNVHRMBAf8EAjAAMCEGA1UdIAQaMBgwCgYIKoIUAEwEgUswCgYIKoIUAEwEgSMwHwYDVR0jBBgwFoAUKPD45qnId8xDRduartc6g6wOD6gwLQYFKyQIAwMEJDAiMCAwHjAcMBowDAwKSURQLURpZW5zdDAKBggqghQATASCBDAOBgNVHQ8BAf8EBAMCB4AwCgYIKoZIzj0EAwIDRwAwRAIgVBPhAwyX8HAVH0O0b3+VazpBAWkQNjkEVRkv+EYX1e8CIFdn4O+nivM+XVi9xiKK4dW1R7MD334OpOPTFjeEhIVV"
      ],
      "kid": "idpSig",
      "kty": "EC",
      "crv": "BP-256",
      "x": "AJZQrG1NWxIB3kz/6Z2zojlkJqN3vJXZ3EZnJ6JXTXw5",
      "y": "ZDFZ5XjwWmtgfomv3VOV7qzI5ycUSJysMWDEu3mqRcY\u003d"
    },
    {
      "x5c": [
        "MIICsTCCAligAwIBAgIHA8OQFtdAtTAKBggqhkjOPQQDAjCBhDELMAkGA1UEBhMCREUxHzAdBgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxMjAwBgNVBAsMKUtvbXBvbmVudGVuLUNBIGRlciBUZWxlbWF0aWtpbmZyYXN0cnVrdHVyMSAwHgYDVQQDDBdHRU0uS09NUC1DQTEwIFRFU1QtT05MWTAeFw0yMTAxMTMwMDAwMDBaFw0yNjAxMTMyMzU5NTlaMEkxCzAJBgNVBAYTAkRFMSYwJAYDVQQKDB1nZW1hdGlrIFRFU1QtT05MWSAtIE5PVC1WQUxJRDESMBAGA1UEAwwJSURQIFNpZyAyMFowFAYHKoZIzj0CAQYJKyQDAwIIAQEHA0IABEC6Sfy6RcfusiYbG+Drx8FNZIS574ojsGDr5n+XJSu8mHuknfNkoMmSbytt4br0YGihOixcmBKy80UfSLdXGe6jge0wgeowDgYDVR0PAQH/BAQDAgeAMC0GBSskCAMDBCQwIjAgMB4wHDAaMAwMCklEUC1EaWVuc3QwCgYIKoIUAEwEggQwIQYDVR0gBBowGDAKBggqghQATASBSzAKBggqghQATASBIzAfBgNVHSMEGDAWgBQo8Pjmqch3zENF25qu1zqDrA4PqDA4BggrBgEFBQcBAQQsMCowKAYIKwYBBQUHMAGGHGh0dHA6Ly9laGNhLmdlbWF0aWsuZGUvb2NzcC8wHQYDVR0OBBYEFLM7Gd6tlX+bjswtS+tVxkbTwxC0MAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwIDRwAwRAIgfKKll8KtEPLdaUWwF7ftbEvkIdz9KXhL4cKRyozGQjECIDxby8TX2iWfwVhfHoxmpTf+D3eCRHhmnwJWcIgm1tF0"
      ],
      "kid": "idpEnc",
      "kty": "EC",
      "crv": "BP-256",
      "x": "QLpJ/LpFx+6yJhsb4OvHwU1khLnviiOwYOvmf5clK7w\u003d",
      "y": "AJh7pJ3zZKDJkm8rbeG69GBooTosXJgSsvNFH0i3Vxnu"
    }
  ]
}
```


