# Basic FLOW 
Log-In attempt using egk with DN 'CN=Juna Fuchs, GIVENNAME=Juna, SURNAME=Fuchs, OU=X114428530, OU=109500969, O=AOK Plus, C=DE'


## Authorization Request 

```
https://<FQDN Server>/<AUTHORIZATION_ENDPOINT>
    ?client_id=eRezeptApp
    &response_type=code
    &redirect_uri=http://redirect.gematik.de/erezept
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'VV5H18ZOyzFbn3s9olpq'>
    &code_challenge=<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: K_fnmI2sWhNmfUnaZoWnzXEk6hr3InmGxsgAG9VRRb4>
    &code_challenge_method=S256
    &scope=openid+e-rezept
    &nonce=<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: '8ZlY1Fg1LPAaALt2Go4t'>

```

## Authorization Response 

```
200
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Transfer-Encoding=chunked,
Date=<Zeitpunkt der Antwort. Beispiel 'Fri, 12 Mar 2021 07:45:07 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "challenge": {
    "rawString": "eyJhbGciOiJCUDI1NlIxIiwiZXhwIjoxNjE1NTM1Mjg3LCJ0eXAiOiJKV1QiLCJraWQiOiJpZHBTaWcifQ.eyJpc3MiOiJodHRwczovL2lkcC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJzbmMiOiJGUUtUU0FLUy1vX1Z0VDMyS0cwV21LclRic2E0UldKQ0lZV2tONTNLcGNFPSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJ0b2tlbl90eXBlIjoiY2hhbGxlbmdlIiwibm9uY2UiOiI4WmxZMUZnMUxQQWFBTHQyR280dCIsImNsaWVudF9pZCI6ImVSZXplcHRBcHAiLCJzY29wZSI6Im9wZW5pZCBlLXJlemVwdCIsInN0YXRlIjoiVlY1SDE4Wk95ekZibjNzOW9scHEiLCJyZWRpcmVjdF91cmkiOiJodHRwOi8vcmVkaXJlY3QuZ2VtYXRpay5kZS9lcmV6ZXB0IiwiZXhwIjoxNjE1NTM1Mjg3LCJpYXQiOjE2MTU1MzUxMDcsImNvZGVfY2hhbGxlbmdlIjoiS19mbm1JMnNXaE5tZlVuYVpvV256WEVrNmhyM0lubUd4c2dBRzlWUlJiNCIsImp0aSI6IjIyNzIxZmZkOWZiYTgxMDEifQ.ZjKcG9aSAg2na-26b3buy_0W4nJl7TuNk3pwh3GICYFgtM-jQPrQZ7WivBJhM-G5-tP-istRlVUqcTD_kCczcg"
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
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1615535287'>",
  "typ": "JWT",
  "kid": "idpSig"
}
{
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'FQKTSAKS-o_VtT32KG0WmKrTbsa4RWJCIYWkN53KpcE='>",
  "code_challenge_method": "S256",
  "token_type": "challenge",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: '8ZlY1Fg1LPAaALt2Go4t'>",
  "client_id": "eRezeptApp",
  "scope": "openid e-rezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'VV5H18ZOyzFbn3s9olpq'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1615535287'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1615535107'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: K_fnmI2sWhNmfUnaZoWnzXEk6hr3InmGxsgAG9VRRb4>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '22721ffd9fba8101'>"
}
```


## Authentication Request 

```
https://<FQDN Server>/<AUTHORIZATION_ENDPOINT>
Multiparts:
signed_challenge=eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJjdHkiOiJKV1QiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiREYySEFWNGJKYXJ4VFpXblkwUmFCcm1pdzlYSE9BTnEtNVljSjVVZU9ucyIsInkiOiJuTFhZZFZSbWtxYUpSQTgxYVpJVWs4RUFhdk42MTVnTVMzQjJ4N1ZhbVFrIiwiY3J2IjoiQlAtMjU2In19.9M6xbN_5ieUZRSiDLZVXhvpb-SwbcS9826vMb6k9f0gEVXAkx7EFDg.a9RFQl0lLvJV4Ppd.g0Sb4DNoe43U4ODTPIn-fdlKA7YJJn2xamMNZWZ3dWqsw3_ALPYVJmkFB9YUJks6FikAUD6hUZAkwhes6ypV6fWaO9O3YuhB_s4EzYtBBGvLV3GDt11lXLWtz-43NIm2fbeqMGmj7XPfhmogVd-qe7S9MxX7NFCCXlnv0TOkeia0UsQUPZlBvyW7JynABCDmNxbWvNIsDf_A8NUszkbuxvkNuDFDuJcwNQx5s_F5s_Ueyc_nS-iAsvJ-goJQwAcy30ZKpD0iHERWHOTnA7A7mv89wQUt4VynELEptNzojE1RDo3W1K6BkFg1H72Zg61Ie-RCTP21ZpKXW89b6toeuGq_xooI6CJBhUtFQbo858KS2JooQmTEeBeSumcX8vzOb8UK6nD6rM5oPelknUII3kKjhTsOCtbLdmjR7PoSo_LjWvK-v_xmiJleeOU4MTg28nkISeVBMSVUglUdaJzls3vx4u3o9gvnxcIiCI7L6Adayh9OBHt4icPLG6kvpPBDG5hCa-uU59q1yxtO58S5m_MBMKKkeYBAYspqHXhtzTE3AtvatpZBrNT1_1D_jilwGtNkQOTOuC8UG3OLOcl-4ezsIhBYi4-jSF30p_TDuzWiDSZwSPtQu2MNWO50g409nka2S1uRs-VM1cVFnQG83TnLRUyH_fKxZKh3GcLeB_vJddJtCFVzgdANyPInNkVs6HPpRMWK4HPCTQ1DgDWUIFsiq2Cir8k7viA8evs2nEXmEaU5DMtfkb8qk6zUKmwEoF_nrsFSuqtL7UXneX1Qmkr-sM1NmJYOSWPpl_9kU7HPL2y18_cBJwC9iABR5MRJo8rR_JWwYEUD01GXlbgv8InbkcL0yAxx1koDgfzdLnhduGt2J8sqY0yMRLom99ixHSIajArsxu9aE5FTEi2mTmR_en6oNofq6TJajerkjYrwieL0ClEJjFXU3qG9Otr36IucdWwn3Uobz7srdlkusDmKmFWMysnQoSwdfkW_632j5zxeZthGRMmYkxE1-mF9cPiWuNByO5EPqzvCq9tDrQdUaYDIovZebpVeqL9gdyC_f6QzZZfAsGreH-cne9nUraspHePhp1OY1W-ITl9OTpFea_mErROkYExE-vAmJru-3537btzjiqV8uuMyYNmS2aTepgXYosBYjfjC7YDZMYWLTItLFStLLIFcBNv3pOZPKjGlk2XBeJyP2yLbh85o6iRlFDF4rKDGWjCp9dBQUuD8aonsvR3btmz_mvzGHAWTKk9IQEVF1MNDbrvpWIFgVlSx_2kaSchAtNDKQ9wUXygQBglo5grrn5t8m_seltHD-z09cvF-jspKaLp_DYu4_V_7NDUxG18RmoRUMVaU1mcy3snsw4TlevfakuT_hdwYyjnRb_4yWz7F__ZIFFh0sHUU_PK09Vbx9N6Y6FFThL3xC6zyZ09GGCo5EOtzMcJuD1hyA1KDPmN2BWacw7DEkaGEwChUEzaJOBBt01C727NaejRZU36ifqCL4BKMJ8Jmq7nfhJrhszvtrS9sXMm9MP4Rq0rUArb0sfXDfXtQgEp-pQUP-b4cjViF-LzXEp7ctu9GPUuHaoAreOQkjxEaNMOfwrN1UPk5ScOYT_R4xFhAxLshVDef7m995B1YCf1sf68AtrzZd63-Xvu3f7KafU6cHtN9oZD1ABX8BYl5ZAQNfIel5xfsuQty8QfMIh7_5OAp7b4lkZIIf-MiErH04nz_BpysZBckb5at_-icm_Ad1__qhuN4ancz1T-m5mCI8Fz_pGjgYXWKJnzZVPCKf4U7in85X_jmQ6zI5sYOnBguqi6ArLscjLVyMM_gIKq0dQ1QSUQgnPL6BW4TSjhO-6bxfbCAMroR-ZpfAAW1UztVUD2oGo9Vrde7JZ5iWJlHxwhlP-hvIDkoEsGQSjGUMiyuM3zlbYRDdxBZHy0fhmv1f92ptd_wlS3ICXSqnSl78gprHyOg6mDSXkUF5SIs3RUgFhbTRwAuE2TyQcX18zf8Y0KaPZ_hf_X806HtD7bvOfg204EPnNI7SGiA0B_By9Axm41GusficaXQLXW7mGwUAPf_KyhtX-HZ6LKgOIU09ByUR0pK3jq5R47ikeX8bO8hwOEz7DwfpeArgzhUwgIx9oZLqapOr3SaCCkNMhI4_NGaKn6H531-8H6n-RY1re4dFldKhhLt3n1H9XsqgnQ4YHiolWWgk_Y3BTa2A11nz2Zh0IS15gkorvfsKMjWEinJKpWF2XAgbeVVgBIRRrKJgDY7xET3x1v7xb26dAy1YoY-v_cCWFup6AjbNesKQ0IV4nlKNqALMUgAHgaeOTcAXzhxU9mgPmfclPjrI-aHJ61QAL-e3zC_zzJ2Mu9OUFckwArpmiGMS9b8lJeVzhN91-6vz9hKYaLejNmpHgOgHdX7r_nn1kamSmD83qMm3OBgR7yHS9PMsOhxLcVMI87jKB-QyyUCEeelmhI8GskoDRCnIiV7eaPzvdVO_Z6i7jV5RbAX6MR02DI_eud9CTWD--611xGhAuTJg2XRjYqy2k7lwSUL6AZeWLuQcYfwC-EFxPd_ZTVvDjsCAOzsQMEnJE3BREWlsw7_XTxozXVQeb0I_3dgoka9zP39uAI_4vCjpIwEOktkoemHwHW66-RLQPabFGMl4SHqRt2ozTVRQzyUjJraEdoCDKmvb68QIBin230wLOKNIp3Ez4CcPzIjozskuPyoDTzOnrovMNELP5TPJWiPdjuAKNRCBgjgLW4A3UFerdtHYOh4vuVqYOPy7mwWa0DxuYZ6Hq5y5oBsHLKAwxEWVLTbJ94qz0tWLu2JWD1lGlAgYsoRQ-ihCm72e-_ahyUkZYlbswd-We1-tMA_yTfJvXXrjfqq0IZL2G66PoG4sywL2HAFSmoEjyyRbKiwI6LdaR24LNEwbzHReNpb43laDUUBmE9jLe-foW1GSLc2KjwbyixlG44QGp4wyj4zNPbDXEa6NxkF3WzwxMtEHU58u5jO2ABOWgUlwrl9MqIj5pThyLAEOCPhWtgIRDvSRpe9zX3H2lOzt7F-avk9VWvnuUR2B2kJYra5IykgIwyxQgoZrtEuj9GmADA5scdnhn3lsV6IhpPQ2eMCw4GWNXE3oYuWSiAif5Vixar3263sqgB5QY0BU26N5cfY9mF-sJizkgjeJzPPD-8XYkGtHvHVu4ZgZ7aXmXYo1avgaKEsqu-5qFgmkDQFw3zYSGq7fTXYsApXBPc4Ix3gQEzKimj_VGfp49nOQ6UNTTl0KNjHz0aJFVbofdufyv72n7GS7xcpkp_zBXolgeL0Kr6QcPFJ3--fBSxU00XS53Ihi7XtYsdJrqTcSVKoq9GXCKyK19y-c23LKbNE9u6ATROckfZBsAMSnfFs80BVv1z9alWNf6C5sDYh4_Ic9oqFjWd5umB323LpvjnNoF0Bh21ocFSJRL251XkbmsHD0I2AAMUbE8So8Sfkm7tvDOhpmA.B_eKw8w6ikByWEvC3HYMdg

```

### Challenge Response (Encryption Header):

```
{
  "alg": "ECDH-ES+A256KW",
  "enc": "A256GCM",
  "cty": "JWT",
  "epk": {
    "kty": "EC",
    "x": "DF2HAV4bJarxTZWnY0RaBrmiw9XHOANq-5YcJ5UeOns",
    "y": "nLXYdVRmkqaJRA81aZIUk8EAavN615gMS3B2x7VamQk",
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
    ?code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE1NTM1MTY3LCJjdHkiOiJKV1QifQ..Jx_uSknIF6KoSnv4.M9tMGm7kEPscMuDrqBeFwi9a6nXpQeV4-Gd72HTubK2I8oNO4KsVuF2bkla5O3YFMtjrpqWK6oDpxqxBO2zk3Zp31f01Jk7K1ZzWP5mNivf-ta7lMhOnJCnCiB8zr51SS86APIedwnnjjk_lvbqj_tw5azsetfggZPnVZBAtCNvOPXYmZC1SY36q6mXfc2It1lSSxfP6ilpSPEFpGaUwzDbK7_qHSGHSoUBZoBixyHcqSr62wwm2KnlT8h80_xjtZ7lwcjrqY-vI4ppaApdGJB3-ZJxFiOJlRxhiU0xtg4TBncAuY1kGSYsFBlDiG8SnUVqozdUaPmuwg5dwUfuqUhxaaIobS_Fb_sJ28lnMuahdr6SwqeCG5FTPyG7qJXb0pvG-vrKApkULaVJN8U9qCPnjuKECKwrxC83IkokwzMgEXgK90--8NCmfC2ODMKeExNa_Nc9hnY9bQdPANuYTl4Xtaosn5gJY1YE4muQ0Ey9Hh5PD0mGooLWYhcDpnNLzOeHc-sPDlydofacs5TnBYQsm11h_3_4Juk8atGLAvy31lcrDVXoYGmi_2jS7TjER8cXfFmXH5LP5Q-GVYou57R1cS4Ftn8II9ZudsYRSBf0inBwZdvJSd0WOYB_1QoeI31r8G-1eHqDiTUdGqbHL2d0DW6E60YeuiiszSTbS9WrBmrAaKvmmCQU1742EZqgQcdORK_b0kGjwNFpz2DCnEvZTttgBRpGs2BvSCYTwIs0imf6fQxrFFo4IHg93tp7zyBwzcRIz2HKCt2ux4qOn1XFwpOYEZAAxV6y7-GRpK1kNy6uueRrCbz_YlvKol_xO41ERMezlrWjcE3GkEM9Aue1OhgctyT9iYHiSZqhlL-kPgnVvZ3PJF8y9d5ZO4aoL2dc6YZqlGh3Yuis8KAbiRRVd4dpXdatIaTiytG5F4y37Krf_Wtp8AMDLT7MxkfDPULfaPaoIFpE5PrJcmbbCjr159gPB8hbvn9rrygR6QcCaZpfBPvOXcHD1AGRHe-pd8KZDEKG78Mn4jJscEnVOT5JIMTe7SOh14YTHjaKrxY7WVKKwT3xyom0z6lVC4BKH08Dw5Wy_Oum1229v-KkGi-8c-KhTr9BQLJk4FWGSNoDtgxtLLJK9ysPzlwKSJoY_fP_foZMaoBZvdjP55NOb2Lx3LGRSN8kSYKRSGNX35AJhd26xEMiDchpzJxLfJn-kf_-hqi4YWebSRRVwwhskzz7nSRSnqEonXeosZQVo8J_u-F1k7tdD1K4nHRS4f3eWT3YeXH-aroBRBRwDbRLSEKXhbVMBI0FJRdIG0V2c.XpgozSRT2r4CVQJ-a4GFNg
    &ssotoken=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE1NTc4MzA3LCJjdHkiOiJKV1QifQ..N1U3zuEONJ9wl0sC.blVOIKegZuKgX_oXj_7yozK-dJWVdWqc8utyV6M7bzF3E8P3rfyyiKD4V66keZstoVLR4fwZt1wukZ42w1n9ga1ihvuyio9nBv4w148dglnx1Zi13i7yqCqm2qDZvz9bQ-AK1_G6a6G3iwqWsSOC2-92WeRwnefV2R97GqGy-rr7xj3cgkWApSgXzXW9Fc7TkMVI42CaC-pFT12d9HSHOdRfrfCUrWi2C-OtLyDBFT7u7hS0Kk33tKS5IxWBzZUK-MQbYrpWBLqHcAau4yx9xPRHmCJNgrCJE9LG58gsNCFvDiD2p5Owk_ul2ZH2ZLGYYuO3m46whQsexIJkEvgrNGQoUEmPf9CmhwcS9PM7o18NLx9E9BRa4DhF1ISxd6SN61FRjH2KxfmHAdwmJ83XYg8-s5sA9PqO5hv6wSHL8tJHyGeD-DGY-GkaNshkdIrLy9FSYfcj2dQKOJ9gPf-6kLsy5s3MugkuIAo88VtQqKdLtPoACJX1TLSuK5xMdBwbgYyd2o4l_bKhWDs3DEvwE9eZLRmjdTI0HPPtWIv5opEmu_WMKt_MbkRn2f196-Nzxf_hiY2dBZS8tZJ4c-4BpaQNAOSKwDcNykAobaGtjqjz-5MULyjfSY0MXdkr_14E5KYCUjXytgW-nzHoiiI7n-dmiRsfleCydbYsyjPNkr-WYhTGkxV5VWTzPAZNkgCq3K9MXkIwQq19eU6w9A5syL5bxy9nn4jroD_u92sSpC-MgBmbje3Kx4bUEmS7MqpaxwH1SWyxmqRzScvraPq1jy7uAdm_TaFrzeFccrKV8aE7Y4O2_XoAytlS-1t0inInyYZ7zuIouoSfCow99pMet974clBMFZvup-UciguaL-rc8OlG8TeZwk7dtK2q7z3tAKm9J6z-h9M3sseT8eMV25t7tbotOXB-BmZ8jk55xeM5I8T52YwQSSJOlYI7n3eBOEF6nb5g-q94sAEPIwgnoI_NcgS-Y_w-CoyE423mCjsZBU7c7CtvwPOR1FVxLWWC53joirRa69u3FNfN1g9DRvXfUFnC6qxyZK32TCQVm9noaUC2nGjarIckLhIjURqBmokdkAxL9ZSNT-9GZ_zPp5XmqsQRZh25RJLdSdicyyfLM6lcxfbmumm8yQldvlO2Xkf2pB5SU-oAM93Dr14suzpJ6zvHm8KMqU92YT0cCQ90H27a8vNFD5o45WqndS_9rb_XCT7a0khBbg9G5W7z-TFC4DxinsBK7gBmh51qWYYNAhtA8IRZ4HeLy6JM_varg1ug0zYK4gslQZB3twYPmPdwlf5NIuKHY22gKlGZ7BL6DGSFauh0SSgAwBlhXiiefgd06E-f9MmcEROh85P_6k49W6eKzpUo5jCqbGDIG0HMBJeABDGizZNWMT65C-QXLELS1H7SxT25ACjt48AGulUkyHBJ6a0YYJ2TAEN6lenx7dJXr0p4yKgRPKc4sLrAN4Rfta5bCT7U89b6PNjMa21EjEwaeyAQpyxO6DVzDwvxL9G3P4TaM7GCsTot3v4BMeyF9DZItnSwoJaGINqbhk8S47m5-DMRFLpVRtSXKlXlZSGxxt-KzUD74HJH22txu54GT_07HIdv6ZuRKmqOFf0lSiDU16BCaextAsKVzI_qAmCU08YyHyvIgXGdOqjCysUI4tcXFib2e1PhCuFQT2CS-EIdoWAJWTCACsse1JYypdy0FPbqjfyeIb-zV046pdbdaOKD1c9wxzIZCJ2AkKPG0O5uOxabxyL6mtzWn4MnFOyx-LeF80uneFghw47VjadCg7vxgaFHWjH10KuvlbT6mpYm2BQK7dsmla4OYSVVhEZOEKX4D3xfQXCbXRaKzvSr2WTdB7YEoFvw0v9CPBGQ6egLKA32zD6gpg8Rq8u9Ik8YKSHHjXLYfngL_5wW3OlZ8DyNdgDAs7El5a3W-6WvOCPx0DtfKiWuPe1Rb8YFn2W7_soRuhXqYJMXiX22V_xRuq8Muy7lerG_AiPLfXbzFq_8XPTQFw_QQflB1DORMobxFTPNDmzzCMURFwPrKz2hqTdOhss1FYIMigaEG4oPZgckCugwEyPMa_JDqMhWBnbs0kBAY6O6GlLPMHi5bhjFTGhrBNw3OgIFYSYNFBfTkbvay2PxTZymG8uAyoj0Os4dg-4JTEOysOQ0svFcw6liSEAG2oVUPtHZZY4go7rVZ_AcXZFu_6KI_VMg_vzYbeUMnpjBDrHi9iflyt7VGsr238Cy5CcippicrByO5CW35R8PzmcUPElogX7flG48lNNtqB-GW_yl-0GE6RdaLWDdRv0KYOSL8ZvilYZ2Y5XTZBik4L2xfFBeODyEsliAJE1Q5lqBxLKjFu-t1wJ-Ki4vWR9ZN_X5-tSUDZj-S0m3snBQh48VuLIZx-23YK-vtttOrmXO4l0qhYA_TVPb9NQNbsBD2OyFbTuspqhg9HVruG9wuY85byXzafDU8p1FsZw44e2gbrKbTYATLrkwRB-3zndxIyQxKLUQNalzvsfdWgx7a7gPUTG6cLT1CuChPQINwKhY1qNfPauF3glchVSA8-QaGRDeYG6uXposoSU8xnpUTdcb5leNpsPSoiRgTvs2F2eR3etMVDZgnBNOVAUmrF3b50ZA5vD-ckhWgt0UrJaOMyWvdA3tV3mXV5S3D6MUX8eTX5HFNHUrZTPnVN9IdxJgyt3iufwY1G6zKZjJmXQ149aAwHjM7qcrNa5gNfqYb56zygQbrTycmdNC9CqrEDNfjwRrLnWOYXjaw_I9Lrgq2zcILyRZ_bkdWCKxb7LnAnqXs5mHbl74.39maBtK_Xfw0vq2OeO_lfw
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'VV5H18ZOyzFbn3s9olpq'>,
Content-Length=0,
Date=<Zeitpunkt der Antwort. Beispiel 'Fri, 12 Mar 2021 07:45:07 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


### Authorization Code (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 1 Minuten. Beispiel: '1615535167'>",
  "cty": "JWT"
}
```


### Authorization Code (Decrypted):

```
{
  "alg": "BP256R1",
  "exp": "<Gültigkeit des Tokens von 1 Minuten. Beispiel: '1615535167'>",
  "typ": "JWT",
  "kid": "idpSig"
}
{
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'DftSq9TWWTB2Srv4AKVD'>",
  "code_challenge_method": "S256",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "token_type": "code",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: '8ZlY1Fg1LPAaALt2Go4t'>",
  "client_id": "eRezeptApp",
  "scope": "openid e-rezept",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1615535107'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'VV5H18ZOyzFbn3s9olpq'>",
  "exp": "<Gültigkeit des Tokens von 1 Minuten. Beispiel: '1615535167'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1615535107'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: K_fnmI2sWhNmfUnaZoWnzXEk6hr3InmGxsgAG9VRRb4>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '73dd053e38444fe6'>"
}
```


### SSO Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1615578307'>",
  "cty": "JWT"
}
```


### SSO Token (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1615578307'>",
  "kid": "idpSig"
}
{
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1615535107'>",
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
                                                              "y": "AJGsJ1cCyGEpCH0ss8JvD4OAHJS8IMm1_rM59jliS-1O"
                                                            }'>",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1615578307'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1615535107'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>"
}
```


## Token Request 

```
https://<FQDN Server>/<TOKEN_ENDPOINT>
Multiparts:
client_id=eRezeptApp
code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE1NTM1MTY3LCJjdHkiOiJKV1QifQ..Jx_uSknIF6KoSnv4.M9tMGm7kEPscMuDrqBeFwi9a6nXpQeV4-Gd72HTubK2I8oNO4KsVuF2bkla5O3YFMtjrpqWK6oDpxqxBO2zk3Zp31f01Jk7K1ZzWP5mNivf-ta7lMhOnJCnCiB8zr51SS86APIedwnnjjk_lvbqj_tw5azsetfggZPnVZBAtCNvOPXYmZC1SY36q6mXfc2It1lSSxfP6ilpSPEFpGaUwzDbK7_qHSGHSoUBZoBixyHcqSr62wwm2KnlT8h80_xjtZ7lwcjrqY-vI4ppaApdGJB3-ZJxFiOJlRxhiU0xtg4TBncAuY1kGSYsFBlDiG8SnUVqozdUaPmuwg5dwUfuqUhxaaIobS_Fb_sJ28lnMuahdr6SwqeCG5FTPyG7qJXb0pvG-vrKApkULaVJN8U9qCPnjuKECKwrxC83IkokwzMgEXgK90--8NCmfC2ODMKeExNa_Nc9hnY9bQdPANuYTl4Xtaosn5gJY1YE4muQ0Ey9Hh5PD0mGooLWYhcDpnNLzOeHc-sPDlydofacs5TnBYQsm11h_3_4Juk8atGLAvy31lcrDVXoYGmi_2jS7TjER8cXfFmXH5LP5Q-GVYou57R1cS4Ftn8II9ZudsYRSBf0inBwZdvJSd0WOYB_1QoeI31r8G-1eHqDiTUdGqbHL2d0DW6E60YeuiiszSTbS9WrBmrAaKvmmCQU1742EZqgQcdORK_b0kGjwNFpz2DCnEvZTttgBRpGs2BvSCYTwIs0imf6fQxrFFo4IHg93tp7zyBwzcRIz2HKCt2ux4qOn1XFwpOYEZAAxV6y7-GRpK1kNy6uueRrCbz_YlvKol_xO41ERMezlrWjcE3GkEM9Aue1OhgctyT9iYHiSZqhlL-kPgnVvZ3PJF8y9d5ZO4aoL2dc6YZqlGh3Yuis8KAbiRRVd4dpXdatIaTiytG5F4y37Krf_Wtp8AMDLT7MxkfDPULfaPaoIFpE5PrJcmbbCjr159gPB8hbvn9rrygR6QcCaZpfBPvOXcHD1AGRHe-pd8KZDEKG78Mn4jJscEnVOT5JIMTe7SOh14YTHjaKrxY7WVKKwT3xyom0z6lVC4BKH08Dw5Wy_Oum1229v-KkGi-8c-KhTr9BQLJk4FWGSNoDtgxtLLJK9ysPzlwKSJoY_fP_foZMaoBZvdjP55NOb2Lx3LGRSN8kSYKRSGNX35AJhd26xEMiDchpzJxLfJn-kf_-hqi4YWebSRRVwwhskzz7nSRSnqEonXeosZQVo8J_u-F1k7tdD1K4nHRS4f3eWT3YeXH-aroBRBRwDbRLSEKXhbVMBI0FJRdIG0V2c.XpgozSRT2r4CVQJ-a4GFNg
grant_type=authorization_code
key_verifier=eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJjdHkiOiJKU09OIiwiZXBrIjp7Imt0eSI6IkVDIiwieCI6Im5MRVJEUmNBQk5NQlJDVllqd3NoVUw2RVFJYlNMa1kzb2xoSG1qT2lObVUiLCJ5IjoiQWVUbHMwRUpSUVNKTFRiTkM1NlBIZl9VZFJfRDhYSTZBSHVpYkVhNVo4TSIsImNydiI6IkJQLTI1NiJ9fQ.i1AGug0iV8AmRZXniFC7G1ZPNJSTLJvNKcsrGpU4vKOUbAig70EENA.Y6GdGNWEa42in53j.EPrWFPxmenySx2HL6srgzpNcpEgSHpEzizJE0X9NrCONKF2kX1y0JMlbFsQBfY2PqSff8AcdYiBRVRtc8EYu5Ww5y1bZDm1e5yjylnbtBJ9g3gPFxfNOeyjDZy1Li03JbtNDw-KSkZ56yN3obIltgm7xY1ERhYZFJTs.VWR8GieI9PblPP1rjIDoCw
redirect_uri=http://redirect.gematik.de/erezept

```

### Key verifier (Encryption Header):

```
{
  "alg": "ECDH-ES+A256KW",
  "enc": "A256GCM",
  "cty": "JSON",
  "epk": {
    "kty": "EC",
    "x": "nLERDRcABNMBRCVYjwshUL6EQIbSLkY3olhHmjOiNmU",
    "y": "AeTls0EJRQSJLTbNC56PHf_UdR_D8XI6AHuibEa5Z8M",
    "crv": "BP-256"
  }
}
```


Key verifier (Body)


```
{
  "token_key": "Y1BFczRtNUowWjhzc0tIck9PWVdXUjZwMnBJTVVaTDU=",
  "code_verifier": "9FxpU0y05JCVvDCEw5ir0ZRptuWd3DRdq0TzTEA1AJE"
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
Date=<Zeitpunkt der Antwort. Beispiel 'Fri, 12 Mar 2021 07:45:07 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "expires_in": 300,
  "token_type": "Bearer",
  "id_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE1NTM1NDA3LCJjdHkiOiJKV1QifQ..p4G_w-AGs2k6mKTH.A81haHKHWLf1bN_ITBWz4szV1DK8IgWpyVVw1laTsayN156AdtCaUlnD4otvIjAvexpGoKQw0Mb_HUIBFsJO6gH9M8Tqd384PdzZTG31viUPruJDmjZF354SPFfzUkVw9Poq3Rn-dRP_mCKXmmRaSkLeK12a6AXYbF3xI5kbZqIxtCJFuUgYJYlLOVA8L7J4xv8mbLOJwWsSdY4teuWm9GKU8ENWpggra1hBD1t7ehG_pzuleZ0u884JsqCp_F7_Yug_WlQiIAxDBliAjhQCVlAKwLI23Q8g2Feist0zgeMlEEQbOI3V7VTRg7kNvf7bFxbqqSjpcsNSozfZ40g5LqGq0x3pGpo2k6-iyOcUEwu3B5TSgN2iXGctD-cfT9Efe8JW-XhSr65DPR7xatWcGwzyClUFkLD1iZ2beGD-vdEou2UomV9O5rF4La_2aCEOn0PuZeELk9V-WKFuZa24ssYpNS2D1PEs_lnHLMs6XQO6xAtnr8yNH6fgNgIS48d2hwzzUzL-3vgyxBDz973P2vPN2L0rDfvYnYoj-J29omxZ2dX9jgMxMVnWBPPQNMmuBkDQ82XOrqt-40XX3z1LAkHzLt154tXUjG2E0rV2LLNeqy6YOUmgsHHvKhVwlZlo6vsrqv_x6R8YJDa39oVsg1Sa2Fs8pgQn07-TQ1JZkTBWEcgPhUlwNQeiO5FMgG_eTd0QZ8eEdyjY3ahLqzCvDAe3aGuvZ6C1Zvv9Jc3paf2B0j0WCq7Vb2PYt9GQO6ucJujipcwPGdzeCW-3l_uSSS5V8Rn0yYaJDJysMbgjvdVhbB-qvmmS4h0ZMXQWQrA5PCj1w8DtH9ee3rhpAjKS_9sJi-G6_GOyOmeJpC_73-Rc8RNxQGXDKWWvuP4ACX23eL4v-jXeNcwUplNCc1VffaIHXFfln3HFk7YeUmDXsEmaN7I02R4PhXOCZxgk3bxv4rVoWqeOzy11u_aESXyYra9AU2okQ8J0VKm2zTWuwW1EZ_g2CSF08oGFc3eff1dwaibjMJw0ckUGNJzKzTPGLGS2W0jEu8LQv_JY6B3w1ODT4xLPQQNiw-VsMX2e_HUyogE5cWm_c6Gk.18eS0sN_W94BWdJjMjqOWw",
  "access_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE1NTM1NDA3LCJjdHkiOiJKV1QifQ..XmPrmMr_zqbxPUZQ.amPMOJ1hd9YFYAj1MQGyjwgxjrAhlcyajMAXgc0d8OPyxqfQwIwfJvgW2rARS_sLRHt_CjGXUlxVcoecRV2QwM9nOU5oRhVw_Uu_7VpnRqbyW85cfWkq9-KBGLg2ALtuj8D3HG2ydPJ7-A5XcV84VxSO5rObzPFy3GBtAfzrfobbwNy3aPvJa74IVp37CsoAzgVfZCJtp2LJ-_hSK9IfkXxqrkVKxWg75_kR9BoK1V9VHLD6bdOaSv7Decre41L9ebJ3SuQ6ZhRPJ3D8V5E0VVIVyKAgBTOaRyX0F2wDF-aTNpPO8ZVraaAQBtztzTMjl3gzplX_BoQQjMvnSwitifznihXU5XsaJr5bJbPODqDypmdKKQmUJ_VWeFTVnZA8MImA0XIhQnWr9UUXaUeoEJKot1inLkrm3nHu5qEl8I6fDGkNfk9Jxwt4ep1htj6qy-l8zBxfMBiTU7zUiOEC2J_-QslVd3VepBMhJ0gQj0lYKq5z0REDMHS9i1LRGhTUaEThQYyr9a-wx_m6kgd7dSgY7YluWhG53lP71giQfPWzaH3tNI5xb5M-1U8wr3XnSod_dfGMO_ZE7JEs1rHam33uJwOiaBvsHHql0eVLPmu0p9UUWHAxr2VMKt7m_O5_T0_wbMwOAQtVlqgFqrMmc9_yYGLQUP6fhD7egsk6fOPRhk_fezTm-6_36bBxl5TTBHP7RZi5lzGxYJp6MJlQq9UK30MVjpsBi6ZA68yi36sRsWLYFVhTgT6yT4IoEmujEnGntf6w9XoxkME5Ct2lbRcPvSV5iOS9eOJUQhYL_oxB5rJVuD1scA_o0zrCnSX8Z8cIfLSrHj7RVQ8QAzI7atVI6KVOIZxcPtzXeQKXprir2GbEQQ_qPOujlze5AgFsD7-t4L2DO0jMTmOQefaLSbudTwHMhAZUgo5Qvs2LKPebvQIFeM4UyFQGSfkWqxqg6g9kuU-o2RGAAJ1P3lX5jivuzhSQP56UZLcRicsjg5EMPvmA74mf15tF2SvJYrtM_7ZthopMrQqp6JUwQAmBZoZPmHpKRnlafhR9RMBvlz9fT3oizz1Z9saWjOCdzaEtyx-8T2Nny33DhGI-9C8eoi3w8g.evDFI75HY7G60vdc_6TBSQ"
}
```


### Access Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1615535407'>",
  "cty": "JWT"
}
```


### Access Token (Decrypted):

```
{
  "alg": "BP256R1",
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
  "scope": "openid e-rezept",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1615535107'>",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1615535407'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1615535107'>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: 'e16c9cb3c3e519b8'>"
}
```


### ID Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1615535407'>",
  "cty": "JWT"
}
```


### ID Token (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "kid": "idpSig"
}
{
  "at_hash": "<Erste 16 Bytes des Hash des Authentication Tokens Base64(subarray(Sha256(authentication_token), 0, 16)). Beispiel: 'WAg_JsiNgHG8aaEOIoa7PA'>",
  "sub": "<subject. Base64(sha256(audClaim + idNummerClaim + serverSubjectSalt)). Beispiel: 'qDAmiQOl5_rJ5-ok48lbjSs6QH9oya7VuxUJ-_E1HCw'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "amr": "["mfa", "sc", "pin"]",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: '8ZlY1Fg1LPAaALt2Go4t'>",
  "aud": "eRezeptApp",
  "acr": "gematik-ehealth-loa-high",
  "azp": "eRezeptApp",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1615535107'>",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1615535407'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1615535107'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: 'b3e0dd5247755971'>"
}
```


# SSO Flow 
## Authorization Request 

```
https://<FQDN Server>/<AUTHORIZATION_ENDPOINT>
    ?client_id=eRezeptApp
    &response_type=code
    &redirect_uri=http://redirect.gematik.de/erezept
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'ium35DOoJCRAUmP6Kaiu'>
    &code_challenge=<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: EMhSSXHkMVGiOGwvMtci59v1slHgQ4yFznp7z8vea8k>
    &code_challenge_method=S256
    &scope=openid+e-rezept
    &nonce=<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'QdxDp3BccO4r9DnbAI6i'>

```

## Authorization Response 

```
200
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Transfer-Encoding=chunked,
Date=<Zeitpunkt der Antwort. Beispiel 'Fri, 12 Mar 2021 07:45:07 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "challenge": {
    "rawString": "eyJhbGciOiJCUDI1NlIxIiwiZXhwIjoxNjE1NTM1Mjg3LCJ0eXAiOiJKV1QiLCJraWQiOiJpZHBTaWcifQ.eyJpc3MiOiJodHRwczovL2lkcC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJzbmMiOiJmczZQdGx5Nk95UVNqOXAxYnZESVZuUVBZNnVrWWlBcC1HRTVPREl1RWU0PSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJ0b2tlbl90eXBlIjoiY2hhbGxlbmdlIiwibm9uY2UiOiJRZHhEcDNCY2NPNHI5RG5iQUk2aSIsImNsaWVudF9pZCI6ImVSZXplcHRBcHAiLCJzY29wZSI6Im9wZW5pZCBlLXJlemVwdCIsInN0YXRlIjoiaXVtMzVET29KQ1JBVW1QNkthaXUiLCJyZWRpcmVjdF91cmkiOiJodHRwOi8vcmVkaXJlY3QuZ2VtYXRpay5kZS9lcmV6ZXB0IiwiZXhwIjoxNjE1NTM1Mjg3LCJpYXQiOjE2MTU1MzUxMDcsImNvZGVfY2hhbGxlbmdlIjoiRU1oU1NYSGtNVkdpT0d3dk10Y2k1OXYxc2xIZ1E0eUZ6bnA3ejh2ZWE4ayIsImp0aSI6ImI0ZWVmN2QzMDdjM2I4MTcifQ.HGjwexsKM_zc2X1WKyVc0VOw1lUfZmU-qU7q2oCYPpsxyz27BGOiE3Jw0GZ5zWUVG34O2_3pYRWmEE8Fbm3wYQ"
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
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1615535287'>",
  "typ": "JWT",
  "kid": "idpSig"
}
{
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'fs6Ptly6OyQSj9p1bvDIVnQPY6ukYiAp-GE5ODIuEe4='>",
  "code_challenge_method": "S256",
  "token_type": "challenge",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'QdxDp3BccO4r9DnbAI6i'>",
  "client_id": "eRezeptApp",
  "scope": "openid e-rezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'ium35DOoJCRAUmP6Kaiu'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1615535287'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1615535107'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: EMhSSXHkMVGiOGwvMtci59v1slHgQ4yFznp7z8vea8k>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: 'b4eef7d307c3b817'>"
}
```


## Authentication Request 

```
https://<FQDN Server>/<SSO_ENDPOINT>
Multiparts:
ssotoken=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE1NTc4MzA3LCJjdHkiOiJKV1QifQ..N1U3zuEONJ9wl0sC.blVOIKegZuKgX_oXj_7yozK-dJWVdWqc8utyV6M7bzF3E8P3rfyyiKD4V66keZstoVLR4fwZt1wukZ42w1n9ga1ihvuyio9nBv4w148dglnx1Zi13i7yqCqm2qDZvz9bQ-AK1_G6a6G3iwqWsSOC2-92WeRwnefV2R97GqGy-rr7xj3cgkWApSgXzXW9Fc7TkMVI42CaC-pFT12d9HSHOdRfrfCUrWi2C-OtLyDBFT7u7hS0Kk33tKS5IxWBzZUK-MQbYrpWBLqHcAau4yx9xPRHmCJNgrCJE9LG58gsNCFvDiD2p5Owk_ul2ZH2ZLGYYuO3m46whQsexIJkEvgrNGQoUEmPf9CmhwcS9PM7o18NLx9E9BRa4DhF1ISxd6SN61FRjH2KxfmHAdwmJ83XYg8-s5sA9PqO5hv6wSHL8tJHyGeD-DGY-GkaNshkdIrLy9FSYfcj2dQKOJ9gPf-6kLsy5s3MugkuIAo88VtQqKdLtPoACJX1TLSuK5xMdBwbgYyd2o4l_bKhWDs3DEvwE9eZLRmjdTI0HPPtWIv5opEmu_WMKt_MbkRn2f196-Nzxf_hiY2dBZS8tZJ4c-4BpaQNAOSKwDcNykAobaGtjqjz-5MULyjfSY0MXdkr_14E5KYCUjXytgW-nzHoiiI7n-dmiRsfleCydbYsyjPNkr-WYhTGkxV5VWTzPAZNkgCq3K9MXkIwQq19eU6w9A5syL5bxy9nn4jroD_u92sSpC-MgBmbje3Kx4bUEmS7MqpaxwH1SWyxmqRzScvraPq1jy7uAdm_TaFrzeFccrKV8aE7Y4O2_XoAytlS-1t0inInyYZ7zuIouoSfCow99pMet974clBMFZvup-UciguaL-rc8OlG8TeZwk7dtK2q7z3tAKm9J6z-h9M3sseT8eMV25t7tbotOXB-BmZ8jk55xeM5I8T52YwQSSJOlYI7n3eBOEF6nb5g-q94sAEPIwgnoI_NcgS-Y_w-CoyE423mCjsZBU7c7CtvwPOR1FVxLWWC53joirRa69u3FNfN1g9DRvXfUFnC6qxyZK32TCQVm9noaUC2nGjarIckLhIjURqBmokdkAxL9ZSNT-9GZ_zPp5XmqsQRZh25RJLdSdicyyfLM6lcxfbmumm8yQldvlO2Xkf2pB5SU-oAM93Dr14suzpJ6zvHm8KMqU92YT0cCQ90H27a8vNFD5o45WqndS_9rb_XCT7a0khBbg9G5W7z-TFC4DxinsBK7gBmh51qWYYNAhtA8IRZ4HeLy6JM_varg1ug0zYK4gslQZB3twYPmPdwlf5NIuKHY22gKlGZ7BL6DGSFauh0SSgAwBlhXiiefgd06E-f9MmcEROh85P_6k49W6eKzpUo5jCqbGDIG0HMBJeABDGizZNWMT65C-QXLELS1H7SxT25ACjt48AGulUkyHBJ6a0YYJ2TAEN6lenx7dJXr0p4yKgRPKc4sLrAN4Rfta5bCT7U89b6PNjMa21EjEwaeyAQpyxO6DVzDwvxL9G3P4TaM7GCsTot3v4BMeyF9DZItnSwoJaGINqbhk8S47m5-DMRFLpVRtSXKlXlZSGxxt-KzUD74HJH22txu54GT_07HIdv6ZuRKmqOFf0lSiDU16BCaextAsKVzI_qAmCU08YyHyvIgXGdOqjCysUI4tcXFib2e1PhCuFQT2CS-EIdoWAJWTCACsse1JYypdy0FPbqjfyeIb-zV046pdbdaOKD1c9wxzIZCJ2AkKPG0O5uOxabxyL6mtzWn4MnFOyx-LeF80uneFghw47VjadCg7vxgaFHWjH10KuvlbT6mpYm2BQK7dsmla4OYSVVhEZOEKX4D3xfQXCbXRaKzvSr2WTdB7YEoFvw0v9CPBGQ6egLKA32zD6gpg8Rq8u9Ik8YKSHHjXLYfngL_5wW3OlZ8DyNdgDAs7El5a3W-6WvOCPx0DtfKiWuPe1Rb8YFn2W7_soRuhXqYJMXiX22V_xRuq8Muy7lerG_AiPLfXbzFq_8XPTQFw_QQflB1DORMobxFTPNDmzzCMURFwPrKz2hqTdOhss1FYIMigaEG4oPZgckCugwEyPMa_JDqMhWBnbs0kBAY6O6GlLPMHi5bhjFTGhrBNw3OgIFYSYNFBfTkbvay2PxTZymG8uAyoj0Os4dg-4JTEOysOQ0svFcw6liSEAG2oVUPtHZZY4go7rVZ_AcXZFu_6KI_VMg_vzYbeUMnpjBDrHi9iflyt7VGsr238Cy5CcippicrByO5CW35R8PzmcUPElogX7flG48lNNtqB-GW_yl-0GE6RdaLWDdRv0KYOSL8ZvilYZ2Y5XTZBik4L2xfFBeODyEsliAJE1Q5lqBxLKjFu-t1wJ-Ki4vWR9ZN_X5-tSUDZj-S0m3snBQh48VuLIZx-23YK-vtttOrmXO4l0qhYA_TVPb9NQNbsBD2OyFbTuspqhg9HVruG9wuY85byXzafDU8p1FsZw44e2gbrKbTYATLrkwRB-3zndxIyQxKLUQNalzvsfdWgx7a7gPUTG6cLT1CuChPQINwKhY1qNfPauF3glchVSA8-QaGRDeYG6uXposoSU8xnpUTdcb5leNpsPSoiRgTvs2F2eR3etMVDZgnBNOVAUmrF3b50ZA5vD-ckhWgt0UrJaOMyWvdA3tV3mXV5S3D6MUX8eTX5HFNHUrZTPnVN9IdxJgyt3iufwY1G6zKZjJmXQ149aAwHjM7qcrNa5gNfqYb56zygQbrTycmdNC9CqrEDNfjwRrLnWOYXjaw_I9Lrgq2zcILyRZ_bkdWCKxb7LnAnqXs5mHbl74.39maBtK_Xfw0vq2OeO_lfw
unsigned_challenge=eyJhbGciOiJCUDI1NlIxIiwiZXhwIjoxNjE1NTM1Mjg3LCJ0eXAiOiJKV1QiLCJraWQiOiJpZHBTaWcifQ.eyJpc3MiOiJodHRwczovL2lkcC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJzbmMiOiJmczZQdGx5Nk95UVNqOXAxYnZESVZuUVBZNnVrWWlBcC1HRTVPREl1RWU0PSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJ0b2tlbl90eXBlIjoiY2hhbGxlbmdlIiwibm9uY2UiOiJRZHhEcDNCY2NPNHI5RG5iQUk2aSIsImNsaWVudF9pZCI6ImVSZXplcHRBcHAiLCJzY29wZSI6Im9wZW5pZCBlLXJlemVwdCIsInN0YXRlIjoiaXVtMzVET29KQ1JBVW1QNkthaXUiLCJyZWRpcmVjdF91cmkiOiJodHRwOi8vcmVkaXJlY3QuZ2VtYXRpay5kZS9lcmV6ZXB0IiwiZXhwIjoxNjE1NTM1Mjg3LCJpYXQiOjE2MTU1MzUxMDcsImNvZGVfY2hhbGxlbmdlIjoiRU1oU1NYSGtNVkdpT0d3dk10Y2k1OXYxc2xIZ1E0eUZ6bnA3ejh2ZWE4ayIsImp0aSI6ImI0ZWVmN2QzMDdjM2I4MTcifQ.HGjwexsKM_zc2X1WKyVc0VOw1lUfZmU-qU7q2oCYPpsxyz27BGOiE3Jw0GZ5zWUVG34O2_3pYRWmEE8Fbm3wYQ

```

### SSO Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1615578307'>",
  "cty": "JWT"
}
```


### SSO Token (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1615578307'>",
  "kid": "idpSig"
}
{
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1615535107'>",
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
                                                              "y": "AJGsJ1cCyGEpCH0ss8JvD4OAHJS8IMm1_rM59jliS-1O"
                                                            }'>",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1615578307'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1615535107'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>"
}
```


### Unsigned Challenge:

```
{
  "alg": "BP256R1",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1615535287'>",
  "typ": "JWT",
  "kid": "idpSig"
}
{
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'fs6Ptly6OyQSj9p1bvDIVnQPY6ukYiAp-GE5ODIuEe4='>",
  "code_challenge_method": "S256",
  "token_type": "challenge",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'QdxDp3BccO4r9DnbAI6i'>",
  "client_id": "eRezeptApp",
  "scope": "openid e-rezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'ium35DOoJCRAUmP6Kaiu'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1615535287'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1615535107'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: EMhSSXHkMVGiOGwvMtci59v1slHgQ4yFznp7z8vea8k>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: 'b4eef7d307c3b817'>"
}
```


## Authentication Response 

```
302
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Location=https://<FQDN Server>//erezept/token
    ?code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE1NTM4NzA3LCJjdHkiOiJKV1QifQ..cfLaeoC0rKbmqE6y.LL-Z2O-363DTZWOxeV9J4F_3KsYeVgpk3qbzL_xhKgIs76vxfVnP5l5PtdmItW9mW48yByF5eq5APCyUh2nrTEgP8gRMs8QDZjQdIk6itFr3lXRiGQKXxOArgzuTrrw_lAAaIDG7OZ7rdb9er7ewGvF0BRRZ593-aGNV6sjy2_xCBnlwImyiisaaDl9QHwdRTLablrOUefBF7Xz05RyWTjY8vFUQa2lw7W-b13lnxYK-bz3718H_QxC38zA_d4Nax--B7LyFWgMyKvv4KzRosF2UoozDTRCb2zIITR6X364O-7ThzCtRHeXbVr-nIeFB44cAFugOUD4Drd4BIqUJhFMb4OqkuqVvpnPmO-uNP2WeQOjUq4lyCk5SF-d3imqlhXd5RuzQl-_UlCl_CWitUaxIlbwavId2kgw3CBxC1V_NR5PT2fh8IU4zLo4RpxhJbrvh1_S6D_4lf5r96CF_z2F7IpdBoZ2F6NcD-18kMp1DZ16JR8UeZazpvtjuRUho4wXeCBNOpap4lN7YHogrgnx3EKJICTScZSSpAzs_uzpcvUQAUws3rmpT3mMQS8yAYGBff4-q_D9TZPr58zTfpIZWh2cqNvS289u9HHIZq3jH4X6KdH9ee9E4eAMwuvNIVBVRvF75kF8mcWomtTbQgT1itXcae06hnPn6bPL6JJ9aX7C3AJb1N0sZY8G8_biR03N78tNx7wnzuGlI5xWfVgBI8w2S63dN1uAwZUybI-ZQ-k9CuH5TsXqcqeVQh762Nq4HnNe10oFrHub0c4rLggbT68yyCWlHgpVMyTwIxdPy__D4QVcpEW_4CKueHIpn7bejuStiAqewxycz-TqhzqfiPrp7WCloTCQWIM2-2G38bu6ZXocd1UmF_re2JTRRXfdvHjJZlLR7oDJ07FuIc9SrqUbpV0WdjYcw_cf4rAyBIVn6Qy4_pPzlpZWYV2WcjyGWAnKGXKXAk-LmnZUZFyPV6_5uKw7PeilUVGZdno4c2xQi5Cfk6-hseLFFt7f15uWy-YFpjh8Je1Oqjpnpzyx2pUGHVHGLdomMFhYLl4uzTXrLHnWingVov2ox9XfDdNi7zNcFxYtrZF-stuB1VwsaMUeYqks7FrMpv6pCmgrlf1s-8w7u7U1-EF2jNSyUVOURdPZSbJwdDejOvzLjX-Jg7bPvNqSvTnn5vLiD3zCjhuJ8qzLgkH5vo1viqlh0PF0rMahEe2T0mIorNB8ZNnqbCsGmFAdna_3XNQcC8-_pYNBzDj1_ja0mHJ2qIylTucle4YtBc0A.O_obeIsSab3tZQBj67Pbew
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'ium35DOoJCRAUmP6Kaiu'>,
Content-Length=0,
Date=<Zeitpunkt der Antwort. Beispiel 'Fri, 12 Mar 2021 07:45:07 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


### Authorization Code (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 1 Stunden. Beispiel: '1615538707'>",
  "cty": "JWT"
}
```


### Authorization Code (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "exp": "<Gültigkeit des Tokens von 1 Stunden. Beispiel: '1615538707'>",
  "kid": "idpSig"
}
{
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'DhWfgM3cnV0t4t0SnUQx'>",
  "code_challenge_method": "S256",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "token_type": "code",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'QdxDp3BccO4r9DnbAI6i'>",
  "client_id": "eRezeptApp",
  "scope": "openid e-rezept",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1615535107'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'ium35DOoJCRAUmP6Kaiu'>",
  "exp": "<Gültigkeit des Tokens von 1 Stunden. Beispiel: '1615538707'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: EMhSSXHkMVGiOGwvMtci59v1slHgQ4yFznp7z8vea8k>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '364ae1af11244434'>"
}
```


## Token Request 

```
https://<FQDN Server>/<TOKEN_ENDPOINT>
Multiparts:
client_id=eRezeptApp
code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE1NTM4NzA3LCJjdHkiOiJKV1QifQ..cfLaeoC0rKbmqE6y.LL-Z2O-363DTZWOxeV9J4F_3KsYeVgpk3qbzL_xhKgIs76vxfVnP5l5PtdmItW9mW48yByF5eq5APCyUh2nrTEgP8gRMs8QDZjQdIk6itFr3lXRiGQKXxOArgzuTrrw_lAAaIDG7OZ7rdb9er7ewGvF0BRRZ593-aGNV6sjy2_xCBnlwImyiisaaDl9QHwdRTLablrOUefBF7Xz05RyWTjY8vFUQa2lw7W-b13lnxYK-bz3718H_QxC38zA_d4Nax--B7LyFWgMyKvv4KzRosF2UoozDTRCb2zIITR6X364O-7ThzCtRHeXbVr-nIeFB44cAFugOUD4Drd4BIqUJhFMb4OqkuqVvpnPmO-uNP2WeQOjUq4lyCk5SF-d3imqlhXd5RuzQl-_UlCl_CWitUaxIlbwavId2kgw3CBxC1V_NR5PT2fh8IU4zLo4RpxhJbrvh1_S6D_4lf5r96CF_z2F7IpdBoZ2F6NcD-18kMp1DZ16JR8UeZazpvtjuRUho4wXeCBNOpap4lN7YHogrgnx3EKJICTScZSSpAzs_uzpcvUQAUws3rmpT3mMQS8yAYGBff4-q_D9TZPr58zTfpIZWh2cqNvS289u9HHIZq3jH4X6KdH9ee9E4eAMwuvNIVBVRvF75kF8mcWomtTbQgT1itXcae06hnPn6bPL6JJ9aX7C3AJb1N0sZY8G8_biR03N78tNx7wnzuGlI5xWfVgBI8w2S63dN1uAwZUybI-ZQ-k9CuH5TsXqcqeVQh762Nq4HnNe10oFrHub0c4rLggbT68yyCWlHgpVMyTwIxdPy__D4QVcpEW_4CKueHIpn7bejuStiAqewxycz-TqhzqfiPrp7WCloTCQWIM2-2G38bu6ZXocd1UmF_re2JTRRXfdvHjJZlLR7oDJ07FuIc9SrqUbpV0WdjYcw_cf4rAyBIVn6Qy4_pPzlpZWYV2WcjyGWAnKGXKXAk-LmnZUZFyPV6_5uKw7PeilUVGZdno4c2xQi5Cfk6-hseLFFt7f15uWy-YFpjh8Je1Oqjpnpzyx2pUGHVHGLdomMFhYLl4uzTXrLHnWingVov2ox9XfDdNi7zNcFxYtrZF-stuB1VwsaMUeYqks7FrMpv6pCmgrlf1s-8w7u7U1-EF2jNSyUVOURdPZSbJwdDejOvzLjX-Jg7bPvNqSvTnn5vLiD3zCjhuJ8qzLgkH5vo1viqlh0PF0rMahEe2T0mIorNB8ZNnqbCsGmFAdna_3XNQcC8-_pYNBzDj1_ja0mHJ2qIylTucle4YtBc0A.O_obeIsSab3tZQBj67Pbew
grant_type=authorization_code
key_verifier=eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJjdHkiOiJKU09OIiwiZXBrIjp7Imt0eSI6IkVDIiwieCI6ImgzdWJRbFJRaXlGRUlCcEpxOVkyaUI3bUpHbFVBN3ByS1FTYmhxbzhfQU0iLCJ5IjoiT2JSM2FMcTJBckRFMUVzaEJUbGNvX1o3cUY2VU1ibG4xdTdUQmt5NkJvUSIsImNydiI6IkJQLTI1NiJ9fQ.l5S31zuKWJ9zqCSSI0SDIM5uwwWla0XvQYGB9x6fIO8Jp1wMlVm9dQ.amBkshnMDXtzm0j_.LcwLENolJ2InSmtj0kYeQ5BZj4PokQPjAq8XP0SFQ8KNwCwSWYXncNSfIIQh_r6XH58DKeuuJJJbqYtP2aH7oCFK9syN_M7t3H03umZYSw59RaHlLsVKqhSH3KpITwS3VLqxoDDnoGZ7_wAjKCKE8xReZx2YtndlQq8.ltTmGAWbJnoydStQxJb1oA
redirect_uri=http://redirect.gematik.de/erezept

```

### Key verifier (Encryption Header):

```
{
  "alg": "ECDH-ES+A256KW",
  "enc": "A256GCM",
  "cty": "JSON",
  "epk": {
    "kty": "EC",
    "x": "h3ubQlRQiyFEIBpJq9Y2iB7mJGlUA7prKQSbhqo8_AM",
    "y": "ObR3aLq2ArDE1EshBTlco_Z7qF6UMbln1u7TBky6BoQ",
    "crv": "BP-256"
  }
}
```


Key verifier (Body)


```
{
  "token_key": "NkJUTXk0cHN3aDFhbFVBZm56NFFNUjR2eXo1MnRiTk0=",
  "code_verifier": "0On0bQ1prKu6Zqb5fSMrrWTRYFU51nDPRt-Nx_wB9J0"
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
Date=<Zeitpunkt der Antwort. Beispiel 'Fri, 12 Mar 2021 07:45:07 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "expires_in": 300,
  "token_type": "Bearer",
  "id_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE1NTM1NDA3LCJjdHkiOiJKV1QifQ..jvtf1SDaQga1udu9.34rdd-xZba31_Ui358V3_2in1G17s6J3_kIEf0__vmMiI6Z8q0PqAPGPpED7FbDIWpnL9gbByBZihC75lmq_xnHvZE4NyktvyfeS7MTYNI5fNqYQufxTm6IiCrwxnMSQKWIKBMhzSaAfSQ0QUvvKo-W4cLY3_-TLFJ6c2wRWnk4cI_1JvV8dgmiOd44Ng8PsX8RPg-Pcd0Eu_F7gIqjAJWQc7Wzm0l1wYTJkAaYcFvK10s00sP--2mt1XVPmrL_cEbIzIF-AVPB3XNI2ShxzCgmw06AWh7gVHGj-sc5I3blWwyjtsjQJpmRpYVlpkfpZ6TWn1q0W1N1xpR3feBUkp9JfYf91LJMuSsNhvwKZjnfePqEBSMgFnKP8e4nlX-2bsSPniKMGvKmGh5DJvejEgdsNnd7TmOEtZY8txS_zr3Le6OZDuWn32BmkWOIPqMGw8QmU1p4w1en1IgNBZW-N4VEEZEw6jmdChi-OLmV65gMbeH2Z9WQDQCfHJy6K44Y8T86nLm7fB9MR-lJWuhmMG6aEv84V6R1Q7Zpjjp-MDulIECChAh423kXgtmJmY6AJ-nQzXUfwY7tVzzj1fBwODnDREISZKbz7qSO40EMnMlYRcNCX24-ogbHZ2ff1YlLIxroVbp373FHdDGq2SInGEoHSmXlBvueUnsiX5r9LLrrg4SOXk8oJBsalp2l1Ys0eV29KtpBTEBWeu5CHpt1fP4hmuUYHZzp_yijb0YJMbHBpE9yu3vJEJHfUhAlMYKwGIraoD9w1oW3ZxUPgH5JItnxM9feF7rmFHMdGsfSWEo4xO0Jt9JlslVpJW5vBr7VO2Elq_i4jEb8Sq0j649DNCTv_lezwVnWNaj7IEJhR-8YQwApNJgVFFXBOm1STKtrldTrnMIT4uikkS9vqEKlGWFFBG3tHfAd_RaLxT8ZX0BMYRj4wsxasxqNo5I_sbAKfKbLVGRTz-jLJ2MqJyuoS79TmGFm_raO_Gv7rGbr5xJgVDJsYak4kYRlggeGCGxYcMrkvR7ci5_E7YGrAJQWLzPuAmNnpLILhBlnp2YhYSasG6Qoyz-TimluRN-Qokd5WBSt1CCzNgDty.yPfRvJVzwoKA66bXWPNPCA",
  "access_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE1NTM1NDA3LCJjdHkiOiJKV1QifQ..Y5ZLBUNLQN8YGO7C.b59oKA2dPPe8owODEn6lwrRw05QsNw7x0S9N5t3EkqV7d9VaIC40xd2rV-Yo-rRwBXZjG2tWQakMPB8ZOLz0KVo73NHmOARtwtTaLkx9JXzBwEAHO3iuGK1sjWA2MY7GrHLBEK2dpIxHIEI3M7dTbIcXT7F8Ia13J9f6Q6F1OgV-llItFDVoRvk2w6aBmVpHWs69xqBjSYvBpl8szK-oSBL49B4Jc8J5pE8iqfITpnZJpGAo9aTPopUku7fQMtPa7D7_glytvQUeY1iYLGyC8KrKzl6LuPm5x0IEiVeUNbf4NlZjKJ6UEUdjqzC8dBpAPTlFCXULD3k_SEHHVYF1B8GxPpQAonIxHHTaXQyfzQ3ueT9s2o02Ea4QcW3-YxtssmmZ1zW184i4DqgOtUP5E6PzWZiRW8lN6QAoScmcaJPAAM1bOFrulOMCKQYWQl1TPDNgisjGO2RxERs95yRlV-tAtCqf2lEHNuswriqHrQGNWgRidDNol_5KzerPUoEP_AjuKWTqqs96GKvcYJeXNhvez-TR3BOIQ9cqzB8Kxp2OROjBwKTqE8DpsTlyk5bYia-v0XRR1px1caIacHDLQmbVesMw_D4ipYzrCyck93rORqStJJTHysCJ8WKN9EFtzxCFFIaJ3wiIPG7dGJliIz_OE0Z8yvkAwrKt0GwOY7MrujKF3U4V5WyQgm90C4GvMIAapkDZqHgw1oe0V-4pb2XOBMrSHD1brv3a2IIU6_byhufwVwJhI1WJPD_U3MmKZXq9d4Aw0rwtqjFdeWOIGUaaSco-12FzXClNz7Sq6tBxEJeEyhQ4Nb2Zbi75wMp6IIKMV45nt6Vxu1hyfFeiXY7SVbOxnTLxbOctjwxOInty-kfHwEZ_P_twJWcWOKccTllyLOLLmOpj4SN0e54Fvp9bKx62aWVmyYbEB7wNHAq3mCZBw697wo6p3DfLo4VUodcu65s4WR2oZp5AElvn0QhPD56Szz1XTTIOKzlQ02junrb6ojB87zxiVIaJSxvNHeOBKrt7QvW5X0t7hFtiY1ejbZfE6N-ca5SVU7F4Musm0D1x_6BXSELd5ylk-Jn2j9X5n1_c6XzTz0p7lBtkOVJlLQ.Di6T-8_u4d60uTReRcW91A"
}
```


### Access Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1615535407'>",
  "cty": "JWT"
}
```


### Access Token (Decrypted):

```
{
  "alg": "BP256R1",
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
  "scope": "openid e-rezept",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1615535107'>",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1615535407'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1615535107'>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '1361f91bce625c0a'>"
}
```


### ID Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1615535407'>",
  "cty": "JWT"
}
```


### ID Token (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "kid": "idpSig"
}
{
  "at_hash": "<Erste 16 Bytes des Hash des Authentication Tokens Base64(subarray(Sha256(authentication_token), 0, 16)). Beispiel: 'MuLDs0Z-I1chLCsHIFkldg'>",
  "sub": "<subject. Base64(sha256(audClaim + idNummerClaim + serverSubjectSalt)). Beispiel: 'qDAmiQOl5_rJ5-ok48lbjSs6QH9oya7VuxUJ-_E1HCw'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "amr": "["mfa", "sc", "pin"]",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'QdxDp3BccO4r9DnbAI6i'>",
  "aud": "eRezeptApp",
  "acr": "gematik-ehealth-loa-high",
  "azp": "eRezeptApp",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1615535107'>",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1615535407'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1615535107'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '8b5ccc26211eb0de'>"
}
```


# Discovery Document 
## http://localhost:57551/discoveryDocument 

```
200
Cache-Control=max-age=300,
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Content-Length=2619,
Date=<Zeitpunkt der Antwort. Beispiel 'Fri, 12 Mar 2021 07:45:07 GMT'>,
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
  "auth_pair_endpoint": "http://localhost:57551/alt_response",
  "sso_endpoint": "<URL des Authorization Endpunkts.>",
  "uri_pair": "http://localhost:57551/pairings",
  "token_endpoint": "<URL des Authorization Endpunkts.>",
  "uri_disc": "<URL des Discovery-Dokuments>",
  "issuer": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "jwks_uri": "<URL einer JWKS-Struktur mit allen vom Server verwendeten Schlüsseln>",
  "exp": "<Gültigkeit des Tokens von PT24H. Beispiel: '1615621507'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1615535107'>",
  "uri_puk_idp_enc": "http://localhost:57551/idpEnc/jwks.json",
  "uri_puk_idp_sig": "http://localhost:57551/ipdSig/jwks.json",
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
  ]
}
```


# JWKS 
## http://localhost:57551/jwks 

```
200
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Transfer-Encoding=chunked,
Date=<Zeitpunkt der Antwort. Beispiel 'Fri, 12 Mar 2021 07:45:07 GMT'>,
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
      "kid": "idpSig",
      "kty": "EC",
      "crv": "BP-256",
      "x": "AJZQrG1NWxIB3kz_6Z2zojlkJqN3vJXZ3EZnJ6JXTXw5",
      "y": "ZDFZ5XjwWmtgfomv3VOV7qzI5ycUSJysMWDEu3mqRcY\u003d"
    },
    {
      "use": "enc",
      "kid": "idpEnc",
      "kty": "EC",
      "crv": "BP-256",
      "x": "QLpJ_LpFx-6yJhsb4OvHwU1khLnviiOwYOvmf5clK7w\u003d",
      "y": "AJh7pJ3zZKDJkm8rbeG69GBooTosXJgSsvNFH0i3Vxnu"
    }
  ]
}
```


