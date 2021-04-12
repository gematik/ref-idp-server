# Basic FLOW 
Log-In attempt using egk with DN 'CN=Juna Fuchs, GIVENNAME=Juna, SURNAME=Fuchs, OU=X114428530, OU=109500969, O=AOK Plus, C=DE'


## Authorization Request 

```
https://<FQDN Server>/<AUTHORIZATION_ENDPOINT>
    ?client_id=eRezeptApp
    &response_type=code
    &redirect_uri=http://redirect.gematik.de/erezept
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'DSWiqasnAuD8PjfvSxWA'>
    &code_challenge=<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: 1Qq8e1XVMOMPCaM7C_T5OEWgzBqN7tPi-HBtxB59wSk>
    &code_challenge_method=S256
    &scope=openid+e-rezept
    &nonce=<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: '77IY9l362ZPMLPsLcveX'>

```

## Authorization Response 

```
200
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Transfer-Encoding=chunked,
Date=<Zeitpunkt der Antwort. Beispiel 'Tue, 06 Apr 2021 15:23:03 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "challenge": {
    "rawString": "eyJhbGciOiJCUDI1NlIxIiwidHlwIjoiSldUIiwia2lkIjoicHVrX2lkcF9zaWcifQ.eyJpc3MiOiJodHRwczovL2lkcC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJzbmMiOiJCUnJmUXI4LTQ5SzZxOHlBZURQWGplb3JBa1Bva2dhUnZpeVExYUdaemtzIiwiY29kZV9jaGFsbGVuZ2VfbWV0aG9kIjoiUzI1NiIsInRva2VuX3R5cGUiOiJjaGFsbGVuZ2UiLCJub25jZSI6Ijc3SVk5bDM2MlpQTUxQc0xjdmVYIiwiY2xpZW50X2lkIjoiZVJlemVwdEFwcCIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0Iiwic3RhdGUiOiJEU1dpcWFzbkF1RDhQamZ2U3hXQSIsInJlZGlyZWN0X3VyaSI6Imh0dHA6Ly9yZWRpcmVjdC5nZW1hdGlrLmRlL2VyZXplcHQiLCJleHAiOjE2MTc3MjI3NjQsImlhdCI6MTYxNzcyMjU4NCwiY29kZV9jaGFsbGVuZ2UiOiIxUXE4ZTFYVk1PTVBDYU03Q19UNU9FV2d6QnFON3RQaS1IQnR4QjU5d1NrIiwianRpIjoiMTNmMTBmNmYyNDUwMTY5MCJ9.U6S2Qcl54sG02HMwo__hn6gg4MxOLSPjJOxkFQE254Z-2aRQ-6ppOZSVvaoZhRcw8cS9dmE1iE1AlhlPbkaLnw"
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
  "typ": "JWT",
  "kid": "puk_idp_sig"
}
{
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'BRrfQr8-49K6q8yAeDPXjeorAkPokgaRviyQ1aGZzks'>",
  "code_challenge_method": "S256",
  "token_type": "challenge",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: '77IY9l362ZPMLPsLcveX'>",
  "client_id": "eRezeptApp",
  "scope": "openid e-rezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'DSWiqasnAuD8PjfvSxWA'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1617722764'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1617722584'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: 1Qq8e1XVMOMPCaM7C_T5OEWgzBqN7tPi-HBtxB59wSk>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '13f10f6f24501690'>"
}
```


## Authentication Request 

```
https://<FQDN Server>/<AUTHORIZATION_ENDPOINT>
Multiparts:
signed_challenge=eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImV4cCI6MTYxNzcyMjc2NCwiY3R5IjoiSldUIiwiZXBrIjp7Imt0eSI6IkVDIiwieCI6ImltQ01DVGV0c0FmSmV4RnJiOHJGQTk5M2gzOHZQVHVGMFZFM2VnSTloNjAiLCJ5IjoiWFZQVWQta0h2a1ZDYzhXa01oOTEtNWN0OF9xTVkxaFZNWkZ3LU4zX3p0byIsImNydiI6IkJQLTI1NiJ9fQ..G59VVLmri_bKJjZo.rgAf0-jDZAiBdh3b3SZS_xJ1UmOYBHrZdKJPq4oYiWGdQtU61e1DDgK-MoQmqprQN3kacEH41_V6Mw9P6YIzt6bBfb3KGQ7TDXCHKeMQlAfnaOqQ37Fi4C1ODCyfkS5uvJ8h4pTJgnN_RgGe0bM-Qq1EXDvDQ59qxpSprzJaxMUFvKFyxRjEarEW-NlofZV5_kboqsv6q4xjIPOc_x4bYhE1OkZ31lGH1HWJZ9m9KXPjqIQ4SQNwgYap1FPmxJRVHL-Vi9HsL_nBFGEoQaBdVr3nowosEloxpzcpbQvkFIO50tszqceqGx5t-Xz_EeRIE1NYf0CeezZDFHcv2MgL09V7lWaYrvzBQh8enD-N7SR-AOIpNs3W94mvZNd6SZO8sOaFJcKPc3AFmhckFAGqk2qE-kWkZWQRtLz4U10Jz7_PXzByB0bdVp1E5rtzL1cYSu3iQUrD1FhJxZzOHg5laUnXKUpGR8Jpr7Mk_3E8FBNHa2JdWpC1cKynE_NBDJLVJ63Boji48Lj6JM3oZKOdZNv60qHV1hqer6HUVm-gk_0WKvFMGLRIj2nfh_Xsj5uLDIApmQDv4iAPt8LWtukp9aMEp0ueUMi_ioOXNdbAC2jmFcsX0_bhG8OsyDdHEq3p3bPunjeV6mwJJXcI1RGixCK2lpZZJ15Eo56QqTeyJG-qCkITlzt-bUOVwGtrNhsFOAG6jSpWpDxquiE1UvDwIWMO017KHA6zJ1goxkl8tZBPv-RScZXr-QhBcNKGj8mwmAYNqyUhgDfT5Bq-2v-jCagyujliRCvJJWWNgRVVc3RaozMxVJFdw9l6_PDsF56CbrH94t5lGGK2PodydP5zdtiA2QTb5QBZjH6q0JchE86XwIKAlUiEYo8sykZN9fT-PiKhuO3HH4x6VKKFJg0lrsiNsE8QzLv1u2kK9CvgpEJztEH6nBOrAwbWqq5UkCw88AYSaoPHTMCcXdd2rHwbnG_vhWN-8OZGIVU0hEisYLTviARGyhRVpyoBU49OmeR2J32Ke5XTY7vDXwzuZyj8-5nJGdEuoODfsO2Nawdv8w6MDKjvQmAs367AyGe5_JW5RmTa8M3nxg-0OrNxIgA-kt15A_J2RF0VjQvy0XHs1mSlIzKTDCqLzOYSI8bHjxssXTbE5xju3wTRe0I9g8R_u13T165V10TQK7fBMwNVUv_g23tzDFwcKaVbrQo8WZe9_y-yAp5gJTypjOYdJp5w2GaH9RCkdznbwSl9z5T40x8HF87rb5mjsV-iRefnJG7QavE6lm7p91NlANJ7QpiKsBocTBZwu8s7AC9mzxsg_80gJmc3mOm1xsLwBPh28j22B81_fH6nCQulimtSniwMBeOf9Ofd6IKP1LpDpr9KqJA9zpBMfMfXx8-L0Tb_8P2uDJllJjr1HlomfCjRiAGeQrt7kC9rBfVBtDd2sCLxHBvjyC9zJVM4Gi7WIGVD8zJ-3ocqAN0pjNHYQh8UFYBm-TjOc3NAawW0bjsrYhtE9MCzHc8rEb0t2BAEty6GTNYSTH1hz43dScoyHWZK-9kxi9pzMP5Cqom5aWHELivinJ6CjXQUUSPvIej2V0E1eNZnLadlinuEEhVX3ko4-SWwXAS_fm6TyMJ_hGYcSP_YYrR1-at0huHKW3qoursnMNsPjJRKGa5Nqs7mgLarhza6kjuymDMtj7GQXmlMQriX5vEaorIuDInGrZ-DQtdey96D-xXYFWH7H52GhU2i9srJE5RFrmVgFcHiK9rFqACkvwsIr8cmBvzheo1GqXZzdLG-umThZk-rjN0oT-U_ov5flo31QabB9cg_ivQIgkmXPbKLKJgnTmBvoEab-MJ0tnrpGptk7E5-lz6-DQNYQwNk5IvLPyFMA3XZ2AiMuKE27o5FkcT3sFuMzeqZMd2e76TAmUC9IInmTSDs0Tc2EoYT_rrog5S088OXGGDPHJPWtFt0NJHp1G99McryHIee9vv71IbMZwlv4MHqOlznGTB5kEhIbEVKbbtJuMhadIaGmZRF6nYEcsNf2oWKmHJN_V5OlZKhiTIO2je44xy4pfwqJvwwBdFk52jGCRlpJeWQq1RfKV2N_TA0seUmRfaiSqJg91pfi6OOBgjoIwgemQ5TxWLq5IQyM0N_PBt9lrOG3dox0mufWXPbCL3PEHyK4mHdEIXN9sdvB52e6NzhKNFI0m0ePX4uYo2Pw7kHg9Ey5Zgyq_TcWJumXnRzrBBL3McvGyF7QBKlm6HtYWJL8Co8KihBfItX70VuE4Ui4v6IOBC4eNhEmFKYFNIicuSm7GMHkLtYZFKYEcH0I-LjzkU9fZYhxK8f-NSQjRhNmQJkgBsGy5urhD4L_v4CBt8JrQiARzCenCX1jiJM6y2IznMpOmoebYqsapwWG4DLZ8yMuYpVfE21JOWS9Fbj5qBL4kwEmOrUh_KQ_c7L_AqX_EGfhvOLnw792AX9yKzpVqEXgbMWLNdk-JZHSmnEyoYBhj9OqvwEE7Q5wz2KEFYLkF5f7E1GDOU23_gBar_S6Hvu5w3Vod3lcQIIPLKbxBcwemFiDbzAbVO0b1YpbhL0cK5--C6DoEuBIvsPdvLI1c_DYxb9hxPFQp4DtxcEekRMFOd_P6FSkoYs2JaPGuMDCj50PVTxyKVl69pJANsybvsId0F33LnWTqZf6z8zdx8v8hP-_CFS69Rr_n7mEZK0L26wihAIh7UcQ2L18I1V29pb49_YkNmmygeD0GdhTidMK9kGqDpHcv4R1MHIcUdlzLzsmyen8TdWXQ35_A54j2It5chT1-CERmGOHGXgfpcUuUYyZG_D2eUbIhHhazN7-Lj7tti0X_RBxPIsdbK5oiMrUj4lBtWakkZsimQ5aCg_rQbJuzHAvQSpigYSZyPkKa8bx7FDj8OCsxySJ3Bs1UpIap2vl5ghPg2hQVBYufcKFmBdeniEkfeTOoC3rXbOTuabcXwJtVvEqm8HsIGDcgGz1svIVN2qFLb-7sFzUmcIW0ApcUcytQ447TRhWl5nKbDVT9TPEM8lgShIQXMAQVXJw8oM2_DPRGHXGjZhnVA8TZphcVbF1ELWxqBc3hO6inoVP5YAURinvthGA0hPBidRC-qw3PGtU9otLjZdrB-E5WHqSvCatc9ARnTGLO5rJsiphUP60AzFeEMjCxza3WcejPd0R2XTjq_NTw-BewpEeAZh_IVbnFirwWg2vWwy8xBCLFMXS-oXAKAy0GP6dUegMhxX-f0Mv26yamdHzU_1ozY2-R1U6-nPqBrgBQNJmEqaGdEoUen0wjR90p49wSI58ZfFUUtGiHbyP0Py0n6alRBPFvc07VasGPKXLAIj2QmR5xtAXA2I9dTSp9dNn6AVwhA1-_4ucavnc4Nv7xG0fUPHV7oLvFFvM-xA28eu1rMr9v9BmLAPRC_hu_4t0fDJo2am3TetWXMlc0LR9tIWUROlGNFhJlV_.AISfViD43TzB1FlE7jjHPw

```

### Challenge Response (Encryption Header):

```
{
  "alg": "ECDH-ES",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1617722764'>",
  "cty": "JWT",
  "epk": {
    "kty": "EC",
    "x": "imCMCTetsAfJexFrb8rFA993h38vPTuF0VE3egI9h60",
    "y": "XVPUd-kHvkVCc8WkMh91-5ct8_qMY1hVMZFw-N3_zto",
    "crv": "BP-256"
  }
}
```


### Challenge Response (Decrypted):

```
{
  "typ": "JWT",
  "cty": "NJWT",
  "alg": "BP256R1",
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
Location=https://<FQDN Server>//erezept
    ?code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE3NzIyNjQ0LCJjdHkiOiJKV1QifQ..Qyp94Nn4AHzU8XYu.EBxoYB8Q2WG5BbiejYRAJZpJvz13wiF-0QREKqqIcJYib2QF-hwI90v6wmynFMjaBfuOVVleveULfDZd-y8ANeTggR3XMCj8girgyw0OO2KlZB6_NBOkrZcsGf40HEYlIoGIztmB4Rq7Pec8goVN3cgqTIJbvEBCU-8YRB-6ih2hk6XO_VBLffKyNs2TBnJbRv5PERMDxrVQJnFm0xVDXtTZcqFu9n0sHIvO3m2ptxbfzuJOiZ1D9x9I0UA4wk_PrrIKZuMEpQ9K1rmvgMdryCPmjZ9zevr3zwDaLnjkevx_Bfl0Pik4_kHk5H8BqAhO7XzDf2ki00QntI-EULbZDwbhinIa1YL31hu3jPdJle6Bk2nCrdF8dkvFerFdzgZRKYbe10wkJ-Ymxad0dtWVgIrGzXw_j3Z19KeFA9sIMcxu-4oIR6LX8BU4Z7Zew6H1HY_wB9cbLm3O9bGFahObmNopZH846ESTec18mMbeSFGTYcrwP7nGbN4-DzA2GzW0xg3-Umge1IvD3d9qlQAaChuVr6Qj17D6hWdek21cvTQYUafj5RnywHLuwQUNyM5aJgAcX6_yS_Yee-PgWPHf0h2O6UA1AkZvFBpyHwJYtdZfybWkAfMz9M3E7dsmDYCBSZ1CgD5SMiTFbG1sPiIq-fS3il01dXvaq1R0ST99gcc0WQ8SclSh5zMCPme2p5UM4u5MZhETThJ5kbPHKgG1IMCPVXo1kevp7UTUNzhegMHpTsX_VZzLEd0AYPID8ByDwMfO7UPyYo3qPBkmNC76T2eELj9woAI-qOjttCVwlRnEso345TJghkNuTKwKCZpD-BpCEccfInmhRhaF1J8JO-_8FqapQ30_B2Bq9hGTho1nG_M5gooUC8p_FKN_yj2yFNU9c_11Jc7ATAtKEM5lzM1RPQF6ulKSpfiRallpSZWafp17RmpfOvV0lD8_kV9I1mX_ulQzDEsk__dyhBPpFhx1hfaJEvIjhhkqIbRbGavnZ6FsW7Y-Cf3S5eAYU99OWaHSi_bfbYetU72_Uiz0tWMincQHRBHw4Q64NoBpR5HU1av_WmDKNf541Lj2Xs3UBMDNulbYMNXPY-tkr6ygQYPqLEH6QKh-luzitDrq1hI2AJ2jf1HC0lnX71s3KpnaQP21Kw3T0qkUXlBsM4mlPJoJJnjd8J4N6DmSpSOlNkPsG42u4WLdcSE9IILn1xN2oUWPe5r9tn6xvUfmbnHC9V20LjkYUsEpktVZTnVDLYICBbImeYyr5vPAEfE14CG2v368YfnMXw.RZV_PYFPmLOFzrm3S9gRyQ
    &ssotoken=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE3NzY1Nzg0LCJjdHkiOiJKV1QifQ..YeDzA2-4axVEWsde.2Owx5CtmMGNTS95s6U0l1XcP1Mh6o9_dGp68y-oqxRocRNtvd3GDY-YCnFaXYHqa31wRMtqfFEKRsF0YflcezxrdCNoZQW9J87BzIyjRkSWfSDmx94RBxEI2XV1Pc8j6t5WYkdtbBPl6bCWFVQgkbRRL6_NmG5dYzaF7ABCuG0oiVXvqIwDAnEsY_trprfcv0jVmNwg0I1hzoLag7v5H5Gj2f9_L65FBoabQymz4LJpVMmyyiNueU2BMZXlCPTxrGlNkDA_p98gipPkBgcgJ6PlEdF9kJbu9LxSGt8kZQ6KH0qx68rjyc1V2Nit0tct-tvMiTLQLdALMv5DBEwmZ2L0nnMNr6rx8WvJoegeaa5ETHsoUyclfIVzDgMjSHDSN-SE3h08TchsNM7ppy7uIeInBbV0A-tZFXOHe4er3rxJVipJGJAY0IUcYVwgYQ423WVTKkTlJd_uVrL7b-abPL9LXHCHD8Q-1JIz2dSHMGtnzAg8sS6rBJkLOsO9xsaqakEg5iucjuKjTUxEpSLvVQmDxXbiM8wdfukGJTLtWk1RCnf1wus1JZKVNzdzLaHnCbN3b0V1ZvgG33ZUPk0Co02W7w2Iy994qr78RcLNShmV3JsNURPvwNdgcZ5xulWDsZVQ3FwxPDxrWRcErjAnLFPu6UgdB50M4tJbcoK2U1mTaacuS_4wzH8a4gqgmM4QGJcdisIvOs2ozO5KRgTFA-Ng0etR-VTD_2rfCaiugUVOncMsC_n-KcHmGM18YFNRCSycJr8egwJORE-ZXkKWlcN2jfhqEM5Tbc4ajfxVRWhgqDXgyFLZaf_mxGx75vg2y_eKlzjkzDLou5x0yLqwRmA5cXPqLZpu-aXk9rFFxxX8cBXxOYvSevEAMrZ_3KADuslcqSWQA9fnt67tPgu1HxfdjyjR6THo_FUi8emqlrV7MY8JFH9LN2DJLWd9WQDU_EPK1bjn4ndee5MXXhrELOco6_ntBE5Bk5cG2d_O1e1FcxsPhPaV5Fn-TsZDj--UnE_ZgWfECVITRNqpy5WHkYwHNJQaG08hgw6YQqVPx-f-ZhgQgRruusSBdwK7Ezs5wwmPYSAXB_2Il8sbVT30rGWShTh2jGTJ5vjdjoGneypF1AfCxt8YEfcdwpP2R9bHPg8r_8M5tTZ4iPma4d_lxzqskbk7WQPzmBN7qLoweXXNsqjZtSYsBECs9geEXNEbh2mP0z0jCyLoo-N_7yhAjOwdCQB94JuHwSHHEPRg0BshvZtAYURN7M7TtsmVfnyeIy2NjesM0Lvx3dHnIMM-liBdB1MTNHJN7sy0_I5C2B1ltiEFGDQqjcTrWahF_ynQ7ASWLUQ9ylYwt0VKGx1Dt66w_gNYyGRX0S37bspXzbCqy9IlS26uY9NNmadG46tB9QFJViGsu7czsRfwI8_ZTq3VYKyzpF4U6ykOtJ8b_tQSOBqWMaanY04AxC4joHJKXwgbp2gcFeDtxYWJ4-CZqg3h3BHBRtaZ7bGZPmbPPuhd688ZagpNm3iJXS0LkNqBqGZ-vcyUwohdRYzeAC3hU5qqsW3QJfV-ekE0b7Dst8O-zHnVqL3MOly0OrgJ9yboE3OmZAXE7foVQeGUmhAUpPDiCUkhuN8-svEkxzwpa7idX86LmXPM-pkpps_TTWadStQRZseBPvKfuZFira-uEmuzEQ0uN2L2-pqid7it-0YW4rZNTNRNLISE8nQSrOMHHyLh7fiNsxlmqf2LZa719AxECs6LurxvPc-1AsQnYekUFyeUDhOECE-srfKiSxiz4DivsqXFkLP370udrU9BlMzwu_E-g2be94XKRh-Ksxyey1i-hbqj4_F_xcsSgmOcFezKT5H_cmmlzjcqep9SjWcZ9YOmrsYkR8ZBzjTLPvLnVHNDXikQM1CEzKJab4kj9XOhkgdLbCI6J5aooCP7GDm9-58A15H1OU63cQlKg5gE6XtPxxkMujz_xdm9uSaA3I0fIkUEbk3U6XOGfS96uiKe8VVsBWsPPJSgn7Bm62zUEcySFxZbWEo9a4948vK7h1k3cx7OFZrhu4p2NFU7Z639AD_IRbKUbr2V86qNHcp2jOZjUbK6sl1sSKfxlO23Q67wZH_QmwVJkZR9XbG5B22-vNIdAsXBRpbs3vo7bkin-hHOnr4eNzZTSnRv2ReZ1z0ypH8U-Y19EB07E_fbooPWfpX2twW_-1P0BYuaBPBGgJA300XaqyuQjLvCCSLLwOml7yMRLq7AATLxGhjLD65eB7eAN8N4vlZ2fQLaNxCxUPomZaU-uAM88tZqRaf-cNxwYzsIR9Tz--ZQEuNBio9o40sAuAg276P5-bCfBP1R7wtpk1LDk2LQLJ7-ZVZqyl1vvXMi_4JRMR_q2GVgfj2n_dCTQsLnCip28gw0yofqFseW_A9hOWgVbxkCZ7UV6HEWoH0JavOq7MquX7C6syFWeZ93onkGtAt_2awPsQBIW0XcfxNiGeHD8ctXcQhV7Exob6gNNbTq7M5PUPIEM4Zl0F9ca54Ciy7wk4SrMSdPSVmcBzvoC-oa7xcgLdaSlE6xUbR1y-fM9faujdVQIKO_yAd80mvzlyu4vh9f1tqXg6AmrxVq8H6_i6vhPMSaIjz6eTcj8nl7VrTG1Ek4eAkIjNBFIMXFrerTUoDVmWHz6nQk0ZUgpVbLNh5ziEUgOt3JOgN8Y6EZaaGfIPy0wN7wx-OhzqdDpgyGH19CejpeV06xgKhnCyE3kHgIdY5r9p_BAyjyzzM414gVktl5w8MlsL50.gdfGwD8FA0wj4uZqyN1e4g
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'DSWiqasnAuD8PjfvSxWA'>,
Content-Length=0,
Date=<Zeitpunkt der Antwort. Beispiel 'Tue, 06 Apr 2021 15:23:03 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


### Authorization Code (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 1 Minuten. Beispiel: '1617722644'>",
  "cty": "JWT"
}
```


### Authorization Code (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "kid": "puk_idp_sig"
}
{
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'AOK Plus'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: '4delfC04k43a0mteVIt3'>",
  "code_challenge_method": "S256",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "token_type": "code",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: '77IY9l362ZPMLPsLcveX'>",
  "client_id": "eRezeptApp",
  "scope": "openid e-rezept",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1617722584'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'DSWiqasnAuD8PjfvSxWA'>",
  "exp": "<Gültigkeit des Tokens von 1 Minuten. Beispiel: '1617722644'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1617722584'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: 1Qq8e1XVMOMPCaM7C_T5OEWgzBqN7tPi-HBtxB59wSk>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: 'be2afa9d09c97ac8'>"
}
```


### SSO Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1617765784'>",
  "cty": "JWT"
}
```


### SSO Token (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "kid": "puk_idp_sig"
}
{
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'AOK Plus'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1617722584'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "cnf": "<confirmation. Authenticated certificate of the client. For details see rfc7800. Beispiel: '{
                                                              "x5c": [
                                                                "MIIC+jCCAqCgAwIBAgIH..."
                                                              ],
                                                              "kid": "844508318621525",
                                                              "kty": "EC",
                                                              "crv": "BP-256",
                                                              "x": "dTXa6yPKCjIr9MbVFxeaLEu82xSCsRrfwcIrLpFqBCs",
                                                              "y": "AJGsJ1cCyGEpCH0ss8JvD4OAHJS8IMm1_rM59jliS-1O"
                                                            }'>",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1617765784'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1617722584'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>"
}
```


## Token Request 

```
https://<FQDN Server>/<TOKEN_ENDPOINT>
Multiparts:
client_id=eRezeptApp
code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE3NzIyNjQ0LCJjdHkiOiJKV1QifQ..Qyp94Nn4AHzU8XYu.EBxoYB8Q2WG5BbiejYRAJZpJvz13wiF-0QREKqqIcJYib2QF-hwI90v6wmynFMjaBfuOVVleveULfDZd-y8ANeTggR3XMCj8girgyw0OO2KlZB6_NBOkrZcsGf40HEYlIoGIztmB4Rq7Pec8goVN3cgqTIJbvEBCU-8YRB-6ih2hk6XO_VBLffKyNs2TBnJbRv5PERMDxrVQJnFm0xVDXtTZcqFu9n0sHIvO3m2ptxbfzuJOiZ1D9x9I0UA4wk_PrrIKZuMEpQ9K1rmvgMdryCPmjZ9zevr3zwDaLnjkevx_Bfl0Pik4_kHk5H8BqAhO7XzDf2ki00QntI-EULbZDwbhinIa1YL31hu3jPdJle6Bk2nCrdF8dkvFerFdzgZRKYbe10wkJ-Ymxad0dtWVgIrGzXw_j3Z19KeFA9sIMcxu-4oIR6LX8BU4Z7Zew6H1HY_wB9cbLm3O9bGFahObmNopZH846ESTec18mMbeSFGTYcrwP7nGbN4-DzA2GzW0xg3-Umge1IvD3d9qlQAaChuVr6Qj17D6hWdek21cvTQYUafj5RnywHLuwQUNyM5aJgAcX6_yS_Yee-PgWPHf0h2O6UA1AkZvFBpyHwJYtdZfybWkAfMz9M3E7dsmDYCBSZ1CgD5SMiTFbG1sPiIq-fS3il01dXvaq1R0ST99gcc0WQ8SclSh5zMCPme2p5UM4u5MZhETThJ5kbPHKgG1IMCPVXo1kevp7UTUNzhegMHpTsX_VZzLEd0AYPID8ByDwMfO7UPyYo3qPBkmNC76T2eELj9woAI-qOjttCVwlRnEso345TJghkNuTKwKCZpD-BpCEccfInmhRhaF1J8JO-_8FqapQ30_B2Bq9hGTho1nG_M5gooUC8p_FKN_yj2yFNU9c_11Jc7ATAtKEM5lzM1RPQF6ulKSpfiRallpSZWafp17RmpfOvV0lD8_kV9I1mX_ulQzDEsk__dyhBPpFhx1hfaJEvIjhhkqIbRbGavnZ6FsW7Y-Cf3S5eAYU99OWaHSi_bfbYetU72_Uiz0tWMincQHRBHw4Q64NoBpR5HU1av_WmDKNf541Lj2Xs3UBMDNulbYMNXPY-tkr6ygQYPqLEH6QKh-luzitDrq1hI2AJ2jf1HC0lnX71s3KpnaQP21Kw3T0qkUXlBsM4mlPJoJJnjd8J4N6DmSpSOlNkPsG42u4WLdcSE9IILn1xN2oUWPe5r9tn6xvUfmbnHC9V20LjkYUsEpktVZTnVDLYICBbImeYyr5vPAEfE14CG2v368YfnMXw.RZV_PYFPmLOFzrm3S9gRyQ
grant_type=authorization_code
key_verifier=eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImN0eSI6IkpTT04iLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiV1oteVNuUzdDTTBCQm1OZmZWWnFkMEJTYmc2dkxlS25VLV9KdXp2VmJsYyIsInkiOiJGSTEyTlFGWk1ORzdjd3ZPYTlUYllXaThXcjh5M2s4emJuT21keWhXUV9RIiwiY3J2IjoiQlAtMjU2In19..o0mr25HjNgJhA8Z7.pfyBTtUmgKhld3EJO5XewkmJ9HhzF26HNrD5-ccikTMcQmLFoQgh1t6iFuLay40U-FfNtY3c0pL2HiyJYjWR9a954NXjbmjPlk3JrVVC0TbTRCsefqlnQ1JqvVcB-qeqO7ZbyxlYlX8UqATsBq9wUFDkQ-f3FwWt4A.jnR_H3vBbLPiqTUab7vWpg
redirect_uri=http://redirect.gematik.de/erezept

```

### Key verifier (Encryption Header):

```
{
  "alg": "ECDH-ES",
  "enc": "A256GCM",
  "cty": "JSON",
  "epk": {
    "kty": "EC",
    "x": "WZ-ySnS7CM0BBmNffVZqd0BSbg6vLeKnU-_JuzvVblc",
    "y": "FI12NQFZMNG7cwvOa9TbYWi8Wr8y3k8zbnOmdyhWQ_Q",
    "crv": "BP-256"
  }
}
```


Key verifier (Body)


```
{
  "token_key": "bXFUcFNaV1FEbW1ucmp2VGZFNGxxZXU5RThFbXQ0NjM",
  "code_verifier": "CpsUC1rQa3MAncislNFtakWgocyp8E4JD8nce5-JKNI"
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
Date=<Zeitpunkt der Antwort. Beispiel 'Tue, 06 Apr 2021 15:23:03 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "expires_in": 300,
  "token_type": "Bearer",
  "id_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE3NzIyODg0LCJjdHkiOiJKV1QifQ..NvshjFyEeu9DajER.edfR7qs9xTe_3sozXgD27UXm3iH3up8acYFsBxgsV4C3fHMqDu9ScfM2pUuNOW4CEqOz5ZSnrsi3_o0dDtvbW2JYUXR6M_l6qiPXIMXXkX9dEIul7xmDV2jiUJIbAd4_6Xh647VesgTU2aUPFpLr-O1nC2XySg29hGTPK9P_kFqzGO5fH4VXjEe6Nl2jwn38kWkQt-xi7DFZ4HUgZwiUwePi9yIpajHu-X8rs_o9mCyfhITNoON4TPggXckNOkn56Ivj7H6NzTOsc8PC7lPj8pTu2gVqIvClfAfowtOfK4sidkcEYbvzIoV8OQqaV22bArDhTLBPEEaqJoRvKpYiQu7EqG4tAGdfNLadtX6JbvBX3-AWyy4nnwURxLIjj232qzuH69qKmIULYN4LjJwDpX54JrKux-TbPhH3OTi2tQpyddMibgvjdVTJc0zb7_QdzbrGsafHP9P_gdBACeBkMR0GBCLAm_Qn7eKKMSr04Zz3EPqFGsoYCGhV6LDD5Dgw4KI-uU7gLdfvyWcdflk3zKbJnb1tMzxQmEwHQ_3H24Jm10KYDNKrp18nd8pnf0a03x8Us4jqZeY1ekGT1PRxxKnF87TASOUN9Xw3Vx90z7F1T1HgvEYI7ZletG02ObeGNVoNmdwYwa-PRy5AnnFkYUBoOg3HpdBit6BcQdFn_dHeJnC_hq1Pm6CU4ZEooR0AIShVG6-yvqR2RMaQaoF681MS0fYhPsH1ufXjptEG1g9ANf6U6sF8pqa-XBYNVYhKqbuJt0IliByfr86zbXxw4uXy6drmwJcBRYoM7irgn4GvbGDlMviEoqEN7LJ5G_uJGTqiAMK2DOx4fNSdHCQVOkBktkVJkKdHjRdWHiuDZJzY8ne9W6Sioktg_8lOiVl-KaDAiEegps4-f9f5nhzA2XE47ASU402cvsYjaT8FVkal-cyy7xoDXOvwglPq22OZEWPzbVF6nvDUihMpK746XpC_toFhjWhtAF0SsLtB3KEb98ntmasB_RkU7dtjbbVTHQ5JBhHbrHgEwCCCPL1rIUIdpe9XzlP9pR4g5mv71tmuMds9_dHFdGOlUxqLd7dq5_vGQ8r1T1zrUCd_MjgIs-YWOjD92F0e5-rHaedewSRKQyakUoTRphpKFzBpu4HVwH-CILlYgVc.r8Kzwef2VlLZqPPz5Mtuzw",
  "access_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE3NzIyODg0LCJjdHkiOiJKV1QifQ..hoJAZ2Cqj9B9ySKX.w8IYcjz-yFNB-Ie2jRoKJCQzHD2jqS9ccf6iKeNx4fWLdahjUoR61N2omOhZbfuPB9AkvFopZsG5UHAgSMNumTWZznW6C8RsDTQmAU3YBdyTmhtrnYn4981zxf-WrKNdAgd1DUAUG_dFfS7fPVmcgTbuuStJFwR0xHbTcmfwb_BfB0cOF-h_hK17eofY91Fp9kVRNVUpL5fPNelywVwX3XtqduUD89kVrJfytiUZqP4Ls93LCaQyyah6KtWE7PvrVOI2xaQkhMuwdBBYiZe-Lyw26xZHPAMmlel1p0P0YbetjWIYU9ZaM0yDXb7eiTxTd_Ec0vQJyWTkoiksGD9_D7ffx0Sdhigq1mfzEA4qzdMkQSpTgnWGobMDpq2C00TAlJn-c1B8w2UXM4tOUqblrAaLWaxDx2WzzWyKXVNsiPSgEMTwBQKAmTE1y3IfLEflRg6muDhNQXPLzTnlWcGy0mfEnkiiyzqPI9YLnsvcFWytmscUB8th3dJ-sthVWJusum_s50AZP1SQ9hwujsCHn_rtIA2zXnaBr7wSpDvXpo2ipmDlprPaQl7JuYq0SCzrdGUx1GZ4GvKO7xO2TgGYQKcCQMiUp5Cb6ykrnME4lysmuDyJzFu6RUXMv8Aa8gcEPNQHMBhLprgCw2z7g_zme1ClxXiTOQYjYHIM1DflqLgixYt4naAycOfC9jFNjd0qFVRaYbNQAeKU1uInjI0oEVwPlcDtmHIhQapxz1vnaZai8IfbY4FcorIDM3ZnKxps1PUY36qsQRqK5d5dCkslJRlVVAvsPFvrl30TjkbiSmHsWRuw5w5GqW0rIW77z1vzZoxRCafcnjTyqS2hRHN17m_hbebiZNWk_YGbhTZ7yPuU_IvbOUeM8L_34VLThRcVOOBEC856jo50jdxiaKbI4v_X61IOn4d5FY29G0JBn8_4dbUIZjqbzO99ziijsB6K6gbzN0gLy7zH7_DLZop1XD5t98SF_fK06jqLtGWiPivoq8kPdtJMORgyjF5nv1OOx4VbDpFeE-Pin2msdP9ZJgkoboYyDu-vE4AIZ1u5DAqpmYRCDfEqWSZQLS5SVWLI5Sr2UAg.R0zREYl5ZfpLGEpgk5PUcQ"
}
```


### Access Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1617722884'>",
  "cty": "JWT"
}
```


### Access Token (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "at+JWT",
  "kid": "puk_idp_sig"
}
{
  "sub": "<subject. Base64(sha256(audClaim + idNummerClaim + serverSubjectSalt)). Beispiel: 'qDAmiQOl5_rJ5-ok48lbjSs6QH9oya7VuxUJ-_E1HCw'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'AOK Plus'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "amr": [
    "mfa",
    "sc",
    "pin"
  ],
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "client_id": "eRezeptApp",
  "aud": "https://erp.telematik.de/login",
  "acr": "gematik-ehealth-loa-high",
  "azp": "eRezeptApp",
  "scope": "openid e-rezept",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1617722584'>",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1617722884'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1617722584'>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '88526f35321c7aff'>"
}
```


### ID Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1617722884'>",
  "cty": "JWT"
}
```


### ID Token (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "kid": "puk_idp_sig"
}
{
  "at_hash": "<Erste 16 Bytes des Hash des Authentication Tokens Base64(subarray(Sha256(authentication_token), 0, 16)). Beispiel: 'SOr-plMw42gKXYCBGitRUg'>",
  "sub": "<subject. Base64(sha256(audClaim + idNummerClaim + serverSubjectSalt)). Beispiel: 'qDAmiQOl5_rJ5-ok48lbjSs6QH9oya7VuxUJ-_E1HCw'>",
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'AOK Plus'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "amr": [
    "mfa",
    "sc",
    "pin"
  ],
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: '77IY9l362ZPMLPsLcveX'>",
  "aud": "https://erp.telematik.de/login",
  "acr": "gematik-ehealth-loa-high",
  "azp": "eRezeptApp",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1617722584'>",
  "scope": "openid e-rezept",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1617722884'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1617722584'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '90a0844f8f41d12b'>"
}
```


# SSO Flow 
## Authorization Request 

```
https://<FQDN Server>/<AUTHORIZATION_ENDPOINT>
    ?client_id=eRezeptApp
    &response_type=code
    &redirect_uri=http://redirect.gematik.de/erezept
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'ytbmXHeLDnWHrKddmrda'>
    &code_challenge=<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: m8Fj-m1Mq4eY8fTPfNoTz4XDh3eSbh9o570b1cjD8mg>
    &code_challenge_method=S256
    &scope=openid+e-rezept
    &nonce=<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'iiXyfRpGUkURJ2ndkGqy'>

```

## Authorization Response 

```
200
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Transfer-Encoding=chunked,
Date=<Zeitpunkt der Antwort. Beispiel 'Tue, 06 Apr 2021 15:23:03 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "challenge": {
    "rawString": "eyJhbGciOiJCUDI1NlIxIiwidHlwIjoiSldUIiwia2lkIjoicHVrX2lkcF9zaWcifQ.eyJpc3MiOiJodHRwczovL2lkcC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJzbmMiOiI2cDllRlQwNEk2MlBHSTdGYndrQzJDeGJYQ0tETUNHOTQ5c1Rqa0NDanlRIiwiY29kZV9jaGFsbGVuZ2VfbWV0aG9kIjoiUzI1NiIsInRva2VuX3R5cGUiOiJjaGFsbGVuZ2UiLCJub25jZSI6ImlpWHlmUnBHVWtVUkoybmRrR3F5IiwiY2xpZW50X2lkIjoiZVJlemVwdEFwcCIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0Iiwic3RhdGUiOiJ5dGJtWEhlTERuV0hyS2RkbXJkYSIsInJlZGlyZWN0X3VyaSI6Imh0dHA6Ly9yZWRpcmVjdC5nZW1hdGlrLmRlL2VyZXplcHQiLCJleHAiOjE2MTc3MjI3NjQsImlhdCI6MTYxNzcyMjU4NCwiY29kZV9jaGFsbGVuZ2UiOiJtOEZqLW0xTXE0ZVk4ZlRQZk5vVHo0WERoM2VTYmg5bzU3MGIxY2pEOG1nIiwianRpIjoiM2MwNWJiM2YxZDIzZGZkMSJ9.lpcoU1DS83axoDbH7fVkemq-pniLjpxb36yTEWWx5siFI02tFKCw3CWVO8rB44ikH4xJRiNIQLX5RZZ8d3BWGw"
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
  "typ": "JWT",
  "kid": "puk_idp_sig"
}
{
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: '6p9eFT04I62PGI7FbwkC2CxbXCKDMCG949sTjkCCjyQ'>",
  "code_challenge_method": "S256",
  "token_type": "challenge",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'iiXyfRpGUkURJ2ndkGqy'>",
  "client_id": "eRezeptApp",
  "scope": "openid e-rezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'ytbmXHeLDnWHrKddmrda'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1617722764'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1617722584'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: m8Fj-m1Mq4eY8fTPfNoTz4XDh3eSbh9o570b1cjD8mg>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '3c05bb3f1d23dfd1'>"
}
```


## Authentication Request 

```
https://<FQDN Server>/<SSO_ENDPOINT>
Multiparts:
ssotoken=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE3NzY1Nzg0LCJjdHkiOiJKV1QifQ..YeDzA2-4axVEWsde.2Owx5CtmMGNTS95s6U0l1XcP1Mh6o9_dGp68y-oqxRocRNtvd3GDY-YCnFaXYHqa31wRMtqfFEKRsF0YflcezxrdCNoZQW9J87BzIyjRkSWfSDmx94RBxEI2XV1Pc8j6t5WYkdtbBPl6bCWFVQgkbRRL6_NmG5dYzaF7ABCuG0oiVXvqIwDAnEsY_trprfcv0jVmNwg0I1hzoLag7v5H5Gj2f9_L65FBoabQymz4LJpVMmyyiNueU2BMZXlCPTxrGlNkDA_p98gipPkBgcgJ6PlEdF9kJbu9LxSGt8kZQ6KH0qx68rjyc1V2Nit0tct-tvMiTLQLdALMv5DBEwmZ2L0nnMNr6rx8WvJoegeaa5ETHsoUyclfIVzDgMjSHDSN-SE3h08TchsNM7ppy7uIeInBbV0A-tZFXOHe4er3rxJVipJGJAY0IUcYVwgYQ423WVTKkTlJd_uVrL7b-abPL9LXHCHD8Q-1JIz2dSHMGtnzAg8sS6rBJkLOsO9xsaqakEg5iucjuKjTUxEpSLvVQmDxXbiM8wdfukGJTLtWk1RCnf1wus1JZKVNzdzLaHnCbN3b0V1ZvgG33ZUPk0Co02W7w2Iy994qr78RcLNShmV3JsNURPvwNdgcZ5xulWDsZVQ3FwxPDxrWRcErjAnLFPu6UgdB50M4tJbcoK2U1mTaacuS_4wzH8a4gqgmM4QGJcdisIvOs2ozO5KRgTFA-Ng0etR-VTD_2rfCaiugUVOncMsC_n-KcHmGM18YFNRCSycJr8egwJORE-ZXkKWlcN2jfhqEM5Tbc4ajfxVRWhgqDXgyFLZaf_mxGx75vg2y_eKlzjkzDLou5x0yLqwRmA5cXPqLZpu-aXk9rFFxxX8cBXxOYvSevEAMrZ_3KADuslcqSWQA9fnt67tPgu1HxfdjyjR6THo_FUi8emqlrV7MY8JFH9LN2DJLWd9WQDU_EPK1bjn4ndee5MXXhrELOco6_ntBE5Bk5cG2d_O1e1FcxsPhPaV5Fn-TsZDj--UnE_ZgWfECVITRNqpy5WHkYwHNJQaG08hgw6YQqVPx-f-ZhgQgRruusSBdwK7Ezs5wwmPYSAXB_2Il8sbVT30rGWShTh2jGTJ5vjdjoGneypF1AfCxt8YEfcdwpP2R9bHPg8r_8M5tTZ4iPma4d_lxzqskbk7WQPzmBN7qLoweXXNsqjZtSYsBECs9geEXNEbh2mP0z0jCyLoo-N_7yhAjOwdCQB94JuHwSHHEPRg0BshvZtAYURN7M7TtsmVfnyeIy2NjesM0Lvx3dHnIMM-liBdB1MTNHJN7sy0_I5C2B1ltiEFGDQqjcTrWahF_ynQ7ASWLUQ9ylYwt0VKGx1Dt66w_gNYyGRX0S37bspXzbCqy9IlS26uY9NNmadG46tB9QFJViGsu7czsRfwI8_ZTq3VYKyzpF4U6ykOtJ8b_tQSOBqWMaanY04AxC4joHJKXwgbp2gcFeDtxYWJ4-CZqg3h3BHBRtaZ7bGZPmbPPuhd688ZagpNm3iJXS0LkNqBqGZ-vcyUwohdRYzeAC3hU5qqsW3QJfV-ekE0b7Dst8O-zHnVqL3MOly0OrgJ9yboE3OmZAXE7foVQeGUmhAUpPDiCUkhuN8-svEkxzwpa7idX86LmXPM-pkpps_TTWadStQRZseBPvKfuZFira-uEmuzEQ0uN2L2-pqid7it-0YW4rZNTNRNLISE8nQSrOMHHyLh7fiNsxlmqf2LZa719AxECs6LurxvPc-1AsQnYekUFyeUDhOECE-srfKiSxiz4DivsqXFkLP370udrU9BlMzwu_E-g2be94XKRh-Ksxyey1i-hbqj4_F_xcsSgmOcFezKT5H_cmmlzjcqep9SjWcZ9YOmrsYkR8ZBzjTLPvLnVHNDXikQM1CEzKJab4kj9XOhkgdLbCI6J5aooCP7GDm9-58A15H1OU63cQlKg5gE6XtPxxkMujz_xdm9uSaA3I0fIkUEbk3U6XOGfS96uiKe8VVsBWsPPJSgn7Bm62zUEcySFxZbWEo9a4948vK7h1k3cx7OFZrhu4p2NFU7Z639AD_IRbKUbr2V86qNHcp2jOZjUbK6sl1sSKfxlO23Q67wZH_QmwVJkZR9XbG5B22-vNIdAsXBRpbs3vo7bkin-hHOnr4eNzZTSnRv2ReZ1z0ypH8U-Y19EB07E_fbooPWfpX2twW_-1P0BYuaBPBGgJA300XaqyuQjLvCCSLLwOml7yMRLq7AATLxGhjLD65eB7eAN8N4vlZ2fQLaNxCxUPomZaU-uAM88tZqRaf-cNxwYzsIR9Tz--ZQEuNBio9o40sAuAg276P5-bCfBP1R7wtpk1LDk2LQLJ7-ZVZqyl1vvXMi_4JRMR_q2GVgfj2n_dCTQsLnCip28gw0yofqFseW_A9hOWgVbxkCZ7UV6HEWoH0JavOq7MquX7C6syFWeZ93onkGtAt_2awPsQBIW0XcfxNiGeHD8ctXcQhV7Exob6gNNbTq7M5PUPIEM4Zl0F9ca54Ciy7wk4SrMSdPSVmcBzvoC-oa7xcgLdaSlE6xUbR1y-fM9faujdVQIKO_yAd80mvzlyu4vh9f1tqXg6AmrxVq8H6_i6vhPMSaIjz6eTcj8nl7VrTG1Ek4eAkIjNBFIMXFrerTUoDVmWHz6nQk0ZUgpVbLNh5ziEUgOt3JOgN8Y6EZaaGfIPy0wN7wx-OhzqdDpgyGH19CejpeV06xgKhnCyE3kHgIdY5r9p_BAyjyzzM414gVktl5w8MlsL50.gdfGwD8FA0wj4uZqyN1e4g
unsigned_challenge=eyJhbGciOiJCUDI1NlIxIiwidHlwIjoiSldUIiwia2lkIjoicHVrX2lkcF9zaWcifQ.eyJpc3MiOiJodHRwczovL2lkcC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJzbmMiOiI2cDllRlQwNEk2MlBHSTdGYndrQzJDeGJYQ0tETUNHOTQ5c1Rqa0NDanlRIiwiY29kZV9jaGFsbGVuZ2VfbWV0aG9kIjoiUzI1NiIsInRva2VuX3R5cGUiOiJjaGFsbGVuZ2UiLCJub25jZSI6ImlpWHlmUnBHVWtVUkoybmRrR3F5IiwiY2xpZW50X2lkIjoiZVJlemVwdEFwcCIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0Iiwic3RhdGUiOiJ5dGJtWEhlTERuV0hyS2RkbXJkYSIsInJlZGlyZWN0X3VyaSI6Imh0dHA6Ly9yZWRpcmVjdC5nZW1hdGlrLmRlL2VyZXplcHQiLCJleHAiOjE2MTc3MjI3NjQsImlhdCI6MTYxNzcyMjU4NCwiY29kZV9jaGFsbGVuZ2UiOiJtOEZqLW0xTXE0ZVk4ZlRQZk5vVHo0WERoM2VTYmg5bzU3MGIxY2pEOG1nIiwianRpIjoiM2MwNWJiM2YxZDIzZGZkMSJ9.lpcoU1DS83axoDbH7fVkemq-pniLjpxb36yTEWWx5siFI02tFKCw3CWVO8rB44ikH4xJRiNIQLX5RZZ8d3BWGw

```

### SSO Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1617765784'>",
  "cty": "JWT"
}
```


### SSO Token (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "kid": "puk_idp_sig"
}
{
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'AOK Plus'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1617722584'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "cnf": "<confirmation. Authenticated certificate of the client. For details see rfc7800. Beispiel: '{
                                                              "x5c": [
                                                                "MIIC+jCCAqCgAwIBAgIH..."
                                                              ],
                                                              "kid": "844508318621525",
                                                              "kty": "EC",
                                                              "crv": "BP-256",
                                                              "x": "dTXa6yPKCjIr9MbVFxeaLEu82xSCsRrfwcIrLpFqBCs",
                                                              "y": "AJGsJ1cCyGEpCH0ss8JvD4OAHJS8IMm1_rM59jliS-1O"
                                                            }'>",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1617765784'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1617722584'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>"
}
```


### Unsigned Challenge:

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "kid": "puk_idp_sig"
}
{
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: '6p9eFT04I62PGI7FbwkC2CxbXCKDMCG949sTjkCCjyQ'>",
  "code_challenge_method": "S256",
  "token_type": "challenge",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'iiXyfRpGUkURJ2ndkGqy'>",
  "client_id": "eRezeptApp",
  "scope": "openid e-rezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'ytbmXHeLDnWHrKddmrda'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1617722764'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1617722584'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: m8Fj-m1Mq4eY8fTPfNoTz4XDh3eSbh9o570b1cjD8mg>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '3c05bb3f1d23dfd1'>"
}
```


## Authentication Response 

```
302
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Location=https://<FQDN Server>//erezept
    ?code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE3NzI2MTg0LCJjdHkiOiJKV1QifQ..m15o0kRF2PARlIu5.mgTnRh22vTqtFOD8TH4w6tXkInQGRtEyQs7LisIWwIRhSeKHwIUb1nLPusl27o1ilj_SdkXrjUNIX3iZselTvm7QK5ky8ADbx7wGD0ZUznGje56lBqp9jflSuLtI6aHhBgDT4NLJnG0Z16CEXs0FXZcHSKq3m-64Saw54MtE9JX6DJsVAHby28JRhjA1ZWXF2mT3OSwBP5AwWhLqSr3V8Ei33-ytHwiDYmJuMtljRsinAttxQlX0tInvDco2lh0wx5FbX4VjPXwuYVTmaOTvmx1dOVZBmGyGjnY4GWaiyE6lSF9cRt0rC5rxHyWLexHXilbUsQfrXHc1e4YomLYUYpIdMXBrHmo-XuhZudhPHLpeWtKbnfmCxHR3JP9f12PO-HEYtMsMrIbA6yurxZSqxr4Oa1gvyTBxz2AMGpxHDJ3tkeUDJrEz9fwMWfQDY9RZihV_nhSF7GLh0vXTmk0qMWw6ogABSrIm1BPVvFm5NUlLJBDa5aZ1Dzcb8KDK14vC-pURaqO45Z0I3OADdHDiVDCA8lA4O2gYjd3q4EkwP_CVWEbxlGN4MA3sNgKd7iwrOl4Lk6srAtKrTiXIFkS-GVyzqhdyLN9GgzPEvb030IuUJTVnkmkOEfPWNSj9V_MQODamiZAPiyIk_zILjnWLVo4UrHzXpafuwhibnBtaVdRylhvpYIo-JTn8cBmprRwjW7SplqR6oQhPE24PyT5gi0CUeutPAfCo6hpwJTW_71pya8faW1eKMp2D4NLYCP4I44FfxWyyGjvZMsmCsORmEpuIeu4fBvUwX8s7ewNPuZ8jud6wSfK2KZGeqdzp2diR8yRZvmsNl6rjfczlf6KrAlgE7cX0pPgvFgVimUCTclK6Stw-ni1JYXr7-4N48P5eRWLOq8-uH4A-I8VCrNHdmCdTglR35W2o1a7MUisGtCairuxJHNcwJ7NzOHf_d_xNKFLv5foUcju85zwdocM3pKdEnvx6NXNx5NpeAjjazAUqvw3-Z1cxXoe4065QLJSrJBzCNP3zVYwnM0B48fD8kZBNf16KqkfyHw80hnLqGt7a_P0fjjwCgPnNxNpMZlCQTQXoto1HaBR--BFWgT0Id5p0TQdqhARS9isFgHSoUA_fpXs3rsFYtibaCukWMg3ouaN7bDXXO7zf4KIvhYPEHeQtMFiI9zaFzEBOHdURTn9eH_4eb1n2UBkJC8_-hRpC8XBo5i25Ow1j_HFTZp_QL-dfDQbz5kj1ibL90kTlsnG6zx72Oarb-E3mL9vCtbhOWcx3Gt5wQw.sl4O84XUQixrzN3bKCSptw
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'ytbmXHeLDnWHrKddmrda'>,
Content-Length=0,
Date=<Zeitpunkt der Antwort. Beispiel 'Tue, 06 Apr 2021 15:23:03 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


### Authorization Code (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 1 Stunden. Beispiel: '1617726184'>",
  "cty": "JWT"
}
```


### Authorization Code (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "kid": "puk_idp_sig"
}
{
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'AOK Plus'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'mJTlmVSj06v29bJdbKhH'>",
  "code_challenge_method": "S256",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "token_type": "code",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'iiXyfRpGUkURJ2ndkGqy'>",
  "client_id": "eRezeptApp",
  "scope": "openid e-rezept",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1617722584'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'ytbmXHeLDnWHrKddmrda'>",
  "exp": "<Gültigkeit des Tokens von 1 Stunden. Beispiel: '1617726184'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1617722584'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: m8Fj-m1Mq4eY8fTPfNoTz4XDh3eSbh9o570b1cjD8mg>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '242ce8f42fe2db2b'>"
}
```


## Token Request 

```
https://<FQDN Server>/<TOKEN_ENDPOINT>
Multiparts:
client_id=eRezeptApp
code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE3NzI2MTg0LCJjdHkiOiJKV1QifQ..m15o0kRF2PARlIu5.mgTnRh22vTqtFOD8TH4w6tXkInQGRtEyQs7LisIWwIRhSeKHwIUb1nLPusl27o1ilj_SdkXrjUNIX3iZselTvm7QK5ky8ADbx7wGD0ZUznGje56lBqp9jflSuLtI6aHhBgDT4NLJnG0Z16CEXs0FXZcHSKq3m-64Saw54MtE9JX6DJsVAHby28JRhjA1ZWXF2mT3OSwBP5AwWhLqSr3V8Ei33-ytHwiDYmJuMtljRsinAttxQlX0tInvDco2lh0wx5FbX4VjPXwuYVTmaOTvmx1dOVZBmGyGjnY4GWaiyE6lSF9cRt0rC5rxHyWLexHXilbUsQfrXHc1e4YomLYUYpIdMXBrHmo-XuhZudhPHLpeWtKbnfmCxHR3JP9f12PO-HEYtMsMrIbA6yurxZSqxr4Oa1gvyTBxz2AMGpxHDJ3tkeUDJrEz9fwMWfQDY9RZihV_nhSF7GLh0vXTmk0qMWw6ogABSrIm1BPVvFm5NUlLJBDa5aZ1Dzcb8KDK14vC-pURaqO45Z0I3OADdHDiVDCA8lA4O2gYjd3q4EkwP_CVWEbxlGN4MA3sNgKd7iwrOl4Lk6srAtKrTiXIFkS-GVyzqhdyLN9GgzPEvb030IuUJTVnkmkOEfPWNSj9V_MQODamiZAPiyIk_zILjnWLVo4UrHzXpafuwhibnBtaVdRylhvpYIo-JTn8cBmprRwjW7SplqR6oQhPE24PyT5gi0CUeutPAfCo6hpwJTW_71pya8faW1eKMp2D4NLYCP4I44FfxWyyGjvZMsmCsORmEpuIeu4fBvUwX8s7ewNPuZ8jud6wSfK2KZGeqdzp2diR8yRZvmsNl6rjfczlf6KrAlgE7cX0pPgvFgVimUCTclK6Stw-ni1JYXr7-4N48P5eRWLOq8-uH4A-I8VCrNHdmCdTglR35W2o1a7MUisGtCairuxJHNcwJ7NzOHf_d_xNKFLv5foUcju85zwdocM3pKdEnvx6NXNx5NpeAjjazAUqvw3-Z1cxXoe4065QLJSrJBzCNP3zVYwnM0B48fD8kZBNf16KqkfyHw80hnLqGt7a_P0fjjwCgPnNxNpMZlCQTQXoto1HaBR--BFWgT0Id5p0TQdqhARS9isFgHSoUA_fpXs3rsFYtibaCukWMg3ouaN7bDXXO7zf4KIvhYPEHeQtMFiI9zaFzEBOHdURTn9eH_4eb1n2UBkJC8_-hRpC8XBo5i25Ow1j_HFTZp_QL-dfDQbz5kj1ibL90kTlsnG6zx72Oarb-E3mL9vCtbhOWcx3Gt5wQw.sl4O84XUQixrzN3bKCSptw
grant_type=authorization_code
key_verifier=eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImN0eSI6IkpTT04iLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiUUZEYm05SWsxRGVUd2s3QnJxNURwd1hjclkta2tQbEFCUjdxWG02VHkzRSIsInkiOiJMYVhJNVk4Z2Nld3ktZE9fZnlNWHQ2aDVEV1E3MUQ2TElJa2w4TXktc0dBIiwiY3J2IjoiQlAtMjU2In19..tHvlPpQo3dhod4CG.D9Hj3x2BVGumvp6A3PiBPH4b9G11SfuFuJcM0FSWXHA0cUW5ZTnQaKRxvnF7bulQbPZNDElEYrTxEmjzd_L3TKxKaXDACZcIaJzBHoLg606L-wh0MZNHJWvH6_3l4_lBA0rc8G9HFn8zjcVK80UHiVWDBAhuZSxGJw.6GVM8h33unMLNM86RciUzQ
redirect_uri=http://redirect.gematik.de/erezept

```

### Key verifier (Encryption Header):

```
{
  "alg": "ECDH-ES",
  "enc": "A256GCM",
  "cty": "JSON",
  "epk": {
    "kty": "EC",
    "x": "QFDbm9Ik1DeTwk7Brq5DpwXcrY-kkPlABR7qXm6Ty3E",
    "y": "LaXI5Y8gcewy-dO_fyMXt6h5DWQ71D6LIIkl8My-sGA",
    "crv": "BP-256"
  }
}
```


Key verifier (Body)


```
{
  "token_key": "eVgzWUNGM0FVWnJFOXdISmlvTkNBN0RHQnl0QXFweDY",
  "code_verifier": "nSRuf8roq9QHUp1qXhi8iPMJoNH1AkuAlCg1zemHyJ4"
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
Date=<Zeitpunkt der Antwort. Beispiel 'Tue, 06 Apr 2021 15:23:03 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "expires_in": 300,
  "token_type": "Bearer",
  "id_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE3NzIyODg0LCJjdHkiOiJKV1QifQ..U4yrUKgLxn8vbSul.Z6GvN9IC-aGAw2LHfEaTpKrbFone7ltNpCLGh0G_OZSlvSjLPdNwtySpofhqcmFFZVY8dGBTCHmPjoJgj6fAnq1xtxY6V2p1pRskc5Mb35so-JDIw9iCYNjJDvsyKeAnryDrW4MCtLrLhQxYc56WoDpLaD5JuPP_HhVKt2bDs0PznW9GzrvyvpkeOLVG5hJckcE7hYYmQ5wJJomoOryOtENw6dwUReTFaDf2bZ99lhkeRDP4-hD1HGEGgSVy9FohMSfe9dPeD2av4hMjlZAFKV_REFEjjD7kD3jhwf00gb9dxToSQpk1U8e5eLZJTBT47OfTNI1uWV9_WO2RyWlb_ByTKumMJ146oZc4faXJJ05gD2CpOB_cKS0PWejJd9q0sYiq1FKzEFDf9zryWWRQ0su_U0eCTRejgT_5M0GIid_h7WgkpUcvf5GobvYRu9MnEho9Hug-L8dR2vVi0kU5th09r307Pw6td7BQD6TlOTFHMtq-Zs5yYL8xad_A4Rg_XNETEG24B6J0YMDvXCjC_rRxijC_4lPWyWiYo0B0CKV9tgKeAlxTL4Acz_XqGN0V3QAgvkaB1WVTy9svglMJUKzqI4dshNM71QZRVhBm30ewnbuYy7tfgYl3dvINAS504FbTaPB_65x6KFAx_AYRjQcpFTLvmtKGf_8lbfTgK3Nu7nvj1iyhjKRSMH1nnWr_lAVLIY1sYlmvyorU53f7fK2oF2bfnmSxNITlYvhS49Vg7gKSaDkaC1DJHlMnYhGMC2u3IGpjPFtqJrFQwg3tCG1PmFJes_OaCvECSaITCH5Pf_Xx2NL7iwrdjOwYryIYp7vhN-VtdInBRUg7TVtlPYp4XM6X-bMZZnAFuiNWC1B5Dr5cTgstQduVBGG-sV0PX5S6tVIVDlUMbRdPwIbmWscnC3eACi23WAbusGh-_3jvDc-Zxfd7P7dMpfZ-4qS3AOW-GeVZ6kgBw7STAMpt85fpSERt4lO45coVB_DnLX8PpnI_pMmMgxXbncGpG4K-hwFu5DT3YpSqmZ2ByQCQ8ZmFhlvE9yi1n4Y63fusUC-yabGsWHOPkvH6mrnj7aYmDGbalM8zgE35xlvZFQcO7WupiG9_MtCmutmhFPcr0Ezk_Ai1VTWM6dVavXWD-aM4FO_Gdn-fF30._FDL6_J6eiv2XP3wQeeGtg",
  "access_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE3NzIyODg0LCJjdHkiOiJKV1QifQ..MWfbyPld4tRRco9z.eOlU_683AMeaWgvbmIlXxGBjo9ulg1_BQg9VcWo9vh8aF6dbh04V5IfHHhd45GAn3cMzBAzdjcwskb_LflnlRXDBCRyyM-2G5c4KqUHt4iqhhKG8HPTV-J18f36PyqcEeJokOE7GuSjf2ixJ1OWLmmzDf4bkbNa2AI5S3rbmFyJuBlfg0ybBbhXaobtUy7lrigB3ryYGhQUFzIk0dkTBmTHDjBTm-BN63cw0eB_Buplniau7V8kLtcWlHmXOoHqKAwVxj4ljQd-Z7BZs8A_gd7-omVyWyCEyQ0VynO5MZBvTa1zvLc0HCPzmn5Or4xhkEC4R_-eQ1tgLiMgdKLzyRuu_TrIDdV3nxFXfaJSaB25rmfQb__6f3kjjzLk7aRGr3UbVyLK9bBSXH42o7mtBcpgjuOqn6lD9vpoRu2mI2wp-ShXtl-f8XgY4-K0-K8kVXxujd4LtGnNszJ7IKAn3EgsyNUAZCIn5Z-gbib6dYCTd0SbTlRyq3Sn-VsbV-Q23z51CGi96lJ6bk4AJq31nnUEpr3stbtC57uwo2xwop9WigP7WQn3k3uT-0iTrfgWXDJaPsWpFE_9w3Es3h-pNBjSu8bJQlKPP9CuNlSe8buIeblHwtIFs1nW059kC_GAKScYLqVBKkll4Ib_18tquoIjeUet4cK7Hq7iKHIjBz3Te0bO4LVwrqiZL9ry-vOOGjiP-qu2f3KOlbdxzRAMOifvcFk8rB22xx6iqO2OiXcIdA9Jnf4R26elGcuWScleddenaJmnRe3WjAgAE_AIoq6cRrQhXuRDi76QtbLQsVoAdyKI6ByVrFrGi3prooGKULWIGzwQM3PhjSFDQkSAFvfWbmzb3f-IYfLPK4VDkXSaoxqpE1Ahzyd0olTofmcvqw8xqJG5Bdo3Akj7BeuOIgrTSN-jAgh4oHDO9DNMVoHkzECSzjbJ7mVxJ4duHIWbwq5TX8vLFchF_hb6gaJMHGmM_Rw1NTu11hW0ghCSkM-5R5Yd0mGkrc0BlXrrcwTkw5FVRAJFsPuK9ib4KIYLLbrN9hBwNnWrN0myFxRSOzQrvO52pZ5_cAV9DfzTadHEHS3x7bc0.vgxvXn5psgFPVy8xXiM3dA"
}
```


### Access Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1617722884'>",
  "cty": "JWT"
}
```


### Access Token (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "at+JWT",
  "kid": "puk_idp_sig"
}
{
  "sub": "<subject. Base64(sha256(audClaim + idNummerClaim + serverSubjectSalt)). Beispiel: 'qDAmiQOl5_rJ5-ok48lbjSs6QH9oya7VuxUJ-_E1HCw'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'AOK Plus'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "amr": [
    "mfa",
    "sc",
    "pin"
  ],
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "client_id": "eRezeptApp",
  "aud": "https://erp.telematik.de/login",
  "acr": "gematik-ehealth-loa-high",
  "azp": "eRezeptApp",
  "scope": "openid e-rezept",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1617722584'>",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1617722884'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1617722584'>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '9c2577ac23a464f2'>"
}
```


### ID Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1617722884'>",
  "cty": "JWT"
}
```


### ID Token (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "kid": "puk_idp_sig"
}
{
  "at_hash": "<Erste 16 Bytes des Hash des Authentication Tokens Base64(subarray(Sha256(authentication_token), 0, 16)). Beispiel: 'ZphWpzQAnQZZVNj43CdXow'>",
  "sub": "<subject. Base64(sha256(audClaim + idNummerClaim + serverSubjectSalt)). Beispiel: 'qDAmiQOl5_rJ5-ok48lbjSs6QH9oya7VuxUJ-_E1HCw'>",
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'AOK Plus'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "amr": [
    "mfa",
    "sc",
    "pin"
  ],
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'iiXyfRpGUkURJ2ndkGqy'>",
  "aud": "https://erp.telematik.de/login",
  "acr": "gematik-ehealth-loa-high",
  "azp": "eRezeptApp",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1617722584'>",
  "scope": "openid e-rezept",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1617722884'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1617722584'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: 'e68e6df6dd5be421'>"
}
```


# Discovery Document 
## http://localhost:52413/discoveryDocument 

```
200
Cache-Control=max-age=300,
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Content-Length=2678,
Date=<Zeitpunkt der Antwort. Beispiel 'Tue, 06 Apr 2021 15:23:03 GMT'>,
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
  "auth_pair_endpoint": "http://localhost:52413/alt_response",
  "sso_endpoint": "<URL des Authorization Endpunkts.>",
  "uri_pair": "http://localhost:52413/pairings",
  "token_endpoint": "<URL des Authorization Endpunkts.>",
  "uri_disc": "<URL des Discovery-Dokuments>",
  "issuer": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "jwks_uri": "<URL einer JWKS-Struktur mit allen vom Server verwendeten Schlüsseln>",
  "exp": "<Gültigkeit des Tokens von PT24H. Beispiel: '1617808984'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1617722584'>",
  "uri_puk_idp_enc": "http://localhost:52413/idpEnc/jwks.json",
  "uri_puk_idp_sig": "http://localhost:52413/ipdSig/jwks.json",
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
    "gematik-ehealth-loa-high"
  ],
  "token_endpoint_auth_methods_supported": [
    "none"
  ],
  "code_challenge_methods_supported": [
    "S256"
  ]
}
```


# JWKS 
## http://localhost:52413/jwks 

```
200
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Transfer-Encoding=chunked,
Date=<Zeitpunkt der Antwort. Beispiel 'Tue, 06 Apr 2021 15:23:03 GMT'>,
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
      "use": "sig",
      "kid": "puk_idp_sig",
      "kty": "EC",
      "crv": "BP-256",
      "x": "AJZQrG1NWxIB3kz_6Z2zojlkJqN3vJXZ3EZnJ6JXTXw5",
      "y": "ZDFZ5XjwWmtgfomv3VOV7qzI5ycUSJysMWDEu3mqRcY"
    },
    {
      "use": "enc",
      "kid": "puk_idp_enc",
      "kty": "EC",
      "crv": "BP-256",
      "x": "QLpJ_LpFx-6yJhsb4OvHwU1khLnviiOwYOvmf5clK7w",
      "y": "AJh7pJ3zZKDJkm8rbeG69GBooTosXJgSsvNFH0i3Vxnu"
    }
  ]
}
```


