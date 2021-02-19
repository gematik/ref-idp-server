# Basic FLOW 
Log-In attempt using egk with DN 'CN=Juna Fuchs, GIVENNAME=Juna, SURNAME=Fuchs, OU=X114428530, OU=109500969, O=AOK Plus, C=DE'


## Authorization Request 

```
https://<FQDN Server>/<AUTHORIZATION_ENDPOINT>
    ?client_id=eRezeptApp
    &response_type=code
    &redirect_uri=http://redirect.gematik.de/erezept
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'UazzivrHoMGsMinyLFO4'>
    &code_challenge=<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: TnbuPTLYhE-mQxSQHRDNn9xARlnLaEhNjZq8M5u_uuw>
    &code_challenge_method=S256
    &scope=e-rezept+openid
    &nonce=<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: '6o2FRVBiSQdOslqQtBw4'>

```

## Authorization Response 

```
200
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Transfer-Encoding=chunked,
Date=<Zeitpunkt der Antwort. Beispiel 'Wed, 17 Feb 2021 08:16:08 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "challenge": {
    "rawString": "eyJhbGciOiJCUDI1NlIxIiwidHlwIjoiSldUIiwiZXhwIjoxNjEzNTQ5OTQ4fQ.eyJpc3MiOiJodHRwczovL2lkcC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwiZXhwIjoxNjEzNTQ5OTQ4LCJpYXQiOjE2MTM1NDk3NjgsInJlc3BvbnNlX3R5cGUiOiJjb2RlIiwic2NvcGUiOiJlLXJlemVwdCBvcGVuaWQiLCJjbGllbnRfaWQiOiJlUmV6ZXB0QXBwIiwic3RhdGUiOiJVYXp6aXZySG9NR3NNaW55TEZPNCIsInJlZGlyZWN0X3VyaSI6Imh0dHA6Ly9yZWRpcmVjdC5nZW1hdGlrLmRlL2VyZXplcHQiLCJjb2RlX2NoYWxsZW5nZV9tZXRob2QiOiJTMjU2IiwiY29kZV9jaGFsbGVuZ2UiOiJUbmJ1UFRMWWhFLW1ReFNRSFJETm45eEFSbG5MYUVoTmpacThNNXVfdXV3IiwidG9rZW5fdHlwZSI6ImNoYWxsZW5nZSIsIm5vbmNlIjoiNm8yRlJWQmlTUWRPc2xxUXRCdzQiLCJzbmMiOiJSc2ZTTnBneGRsVUJOMjRkM0E1SVVKa213QmUwalhNYUJFdDRCdSs2RDRNPSIsImp0aSI6IjY2ZGEzYjcxZTRhN2ViZDYifQ.aSop-v2UiMflkjAcmza3y4tBuryhm8SfBzqF_dtyI9GIF4rg_beLvgrfvHgyCAstbk0OgGjuX3StcBSp0pD2hg"
  },
  "userConsent": [
    "GIVEN_NAME",
    "FAMILY_NAME",
    "ORGANIZATION_NAME",
    "PROFESSION_OID",
    "ID_NUMBER"
  ]
}
```


### Challenge Token:

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1613549948'>"
}
{
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1613549948'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1613549768'>",
  "response_type": "code",
  "scope": "e-rezept openid",
  "client_id": "eRezeptApp",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'UazzivrHoMGsMinyLFO4'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "code_challenge_method": "S256",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: TnbuPTLYhE-mQxSQHRDNn9xARlnLaEhNjZq8M5u_uuw>",
  "token_type": "challenge",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: '6o2FRVBiSQdOslqQtBw4'>",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'RsfSNpgxdlUBN24d3A5IUJkmwBe0jXMaBEt4Bu+6D4M='>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '66da3b71e4a7ebd6'>"
}
```


## Authentication Request 

```
https://<FQDN Server>/<AUTHORIZATION_ENDPOINT>
Multiparts:
signed_challenge=eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiUkFvM0t4aEdwdDd5WXhXX1RtOElBUG94OHg3Y0NGZ2M3eWFzcnNPcEpaQSIsInkiOiJZN0NOdHlDbHNhbWs4bnRuOGlyeXMybGhDU1gzdEFmbTVMUGw1VEJqWjlVIiwiY3J2IjoiQlAtMjU2In19.5wTIyqt6p9w4SSmYrPcJIwQxhw4lBi1brlBvN9xetNJlJjOqxDLZqQ.1lTL4jBcCP1Xbm2L.83icinzfgPQ1Vi_Gyq4BxYRdXUj8E2Q6jNwvZzJFdI3L6Zlq7DvBWuFd-1qcqIPPRo8kwNx7K375Z8-XdzmCeNTB8lB6EqSTfKKfbX-feQF3l7Atv_EiV9POFbxOjKd1eyvAVqPk1l23DZ8-oHAFCXUhf8ENxSL-sAKwELqT-y4AERhgoRa4J4QEz6c2E5Sp6w1ftbNUXNtnVDoJ_VN1nBKe70ztMKawz3g5bEiFu1PkjZbYluPOBZRAckqt0BW_16m-vsSLhbAQKcjYJ7mCl-4elMWwVda7VIsTsxGOQydeQfgFaAVVVMdsS0giWkLAJ7r8Fgnui3Flrjaw5it-CQoesN78hHiEiTTR_I9Z1uTgPl4TGppiZTkgwB9K8vYrrgEAz8jmQSKJXtDjpH_J5A3_UU7kXkJtO_uKaY3gb9zyPFsB1kF9WRFlckZ1H6vucnF3eLdfVp9kdIF5aNXdCycpgBMemKwrnumU2yr-7xSJoqTZFXiSGsTGGLmEhyDYRH8SKC3knhunNvKlthKbcGr7MVKHp23lBGjBr6fVpY-5sQuGwkRhripS4hbdDYhDIyQND6MExFcUOrRHahGpLrdfWr5QSwqjAaZFtO2oZuWJy2EC3igGi4wH6HkQIm13hNxl2cngErODawOeJ84nLalAvBDk5B0UhNBDs8NEYuQwEdVaxyNN6-oIW1JNRdYcx9K057zT1qLy-I-L6htIYxPEdJaREhcP5hMh1CcwKD4idM76UAf4K4YoLFcR9RpyREmaPcjoGRmwy5oiqsNCUa0NsrcAmwtKGmqmwV7X59csPR8Rpd20Rwytg3Tlo5NkJia-6zsFUBRqEFYOTedGbu7pNlFcYb1G4PM_6gNM68MXjSUvGJf3Hf_7N1cQ8K5guFDjN_tcr3p7nTnzAY10gGR5-lpllAaXFVmMTCvzYy8pIu1PzV09LDE5HrGg3cV5-7b1xAZ4TylTMt2ud0mp0Vfc-tpa_1_j5wj0ebXy7ldfTRLOQNGNCLQmZI5Lo5y4dlL_zpDgj93iPlV0TIlBn7aBnE59_BXDjqMQBYzUn0awgXyNjoRpoc44SV6PNYf56dVjyD7fQ9gaOMMjO51QVd-Ezg0mnys1c1jAvSIX3wEuXBGuEIe2xqJVtPfLfyfaYA-r5nQWlz2L89jXwujNaxYXHf-d2j6HQ8CmKIIgLvywbZVXJbj-mUml74A3atnulfu0P9PdZO-W3sL--Ze9akhum5Yrx0YOVLHR5_535DKTG-bCmbUOgkUWzHsN0mGG-P2QGzssOAV3aHfCI6pf-te9qgsoS2GmKx-xllsS8-psFN7PH6s_dClkbBfhEqZeT04_8USS_LAVIrOIaJR0j4ZSo0eYakjl2wDjwaYuzCBXqbK18umU8Bc_a_oU5bUIV0RsdtOf282jsEE5nByU6Thpp4jbk_eHtOLnCLByw_F2orNCbiCUvbyVvU_hHjxXAHicEh4q-gCnIg5S6TOiicWHGGKVsBpjcCbH6eF7EzN3XkCKaOu9OPq5Fpo2j1bhppaS9_cqOHDHCFXj2ULPEWG-f4CKnAmHY21PXxzouSnyyNkPIgEYLZodmcAXvGWGQKJPNnGRiCaIkPcR5LUFXmIUKjS9eOor_ebE99zy6LsYSPDLAS5AphyF67UrQS9Oc7mVjUEVIg2aDQYPt0ELpTVBKcXZ6V96WIJ0rhmhassXZ5xOsdgvyhBA0dUOmVCM_VexityAs20VkoIcOtD86DJVGUYFl469nOzrxJ0PFr7J4NqHfpOuHDmCw8eOo1q1ZXZsK3riVIH_M7OWbGlIPSZAFtmWMKbumViSxTRjFZ-7uAD0QLEUmyOCtPEiULz8xG7S3mBXhpSfKmMLnydLUPwqOhw0LrJ6x53_VHEBl0EIi5q81GRdDV7ISdR2wamP9uzHxUghQcdDwe2ZN0QKIZkPX2Bp1cM8wAxBN56mel32n8koAHoglNcz6oCY5hXklm_nATMpUkWLBWqNjtQYrXbtHmULSzMP52w-oLViok-VxDB9dcoosVEetN6TQs82cEQKrF8nc7G60KF4vIS29zgtBis6hyzmHR4O-Ukj30bxnMY0YDN8ucY3yZdb7PHCaYNGfddLOQSPn5sJ7ICQUd3wSA5yx92qSYHUEX_QjhOeH5TyGa2HjradqfJ4Vk0tm15UmY7weTs6aTtG3JXi5tj7sN98tQZ-URYaUZji00Xi_TriEHdTXZKVhsqo0u57RB3_iFDQ5W_wnlyPKzibkYWBMZNb6Ay16eY5LZ92S2_yOiSISvDCnlMl7b8GWpDCnKxz819RBHmDAPci47qU57QB3WThCPvihECa9Z44FUN26W1JwRGUHIUsmFRy_kP4w-lRnMzuNNWjyXGIoAeygoCdKvEOgekfKwv91C9dG_gvYw22efzmfuQH4jE2dBQsKCrOAwgo-UoXbSNNuhB6dqx4Ix7hSGlfPXJRJVFmYvfemcZFpFuNftuHLt-G2bsC-NmuSKyzC37XYPXiPQCClsoihvV6e3pxAMGbqo-K4nBIkEk93smspyuGHR7F8nu1iedlnK9SHNXUvu-yVCLkO0-yuMrcSsRWTX9zKph_H_jLRb2ihX7J-Z7v-4mT3z6jPP-BiRHvYRupq2EUP-_tQLpesXmjOWD-s6p8Lh79NN4Vh8pySdEvjIXujp8CrfEOWqgEseFr-lJgiYvW4d2znwub_YaHRtHCs4hYGzW0C4k5A-h0boo1ntP1ZujKyHNbtt6qK0SfBbumhdvwQBKI3A72WxnRX5bn-h0sEzapMHWn5OmNeZUuu4_KYQbfjLRWX1K4a-6MEPpucY4WwFh10oYStNHB5IHREXAr9NrdCgDLjSDStnUdBHj_lDxl_rL_5bcMEaZrInDyZMjvKsAYWetL-3k8b_8QwcopRDvWnyRX7vC4J3GkM0qhzOi5Hdk5jHiS-B6jWJgzdY9mqp7ViXgR9i47IBGzaOX9B7XgSxqrhNry74FHzurteCi5qvw0P0xlUnCXbvhaP0-CpI-eyRLPewcav9wI3HKcGt3ium2uAiC-fJWNvkdMO4zesB6Uk_gz4RGnaKFMW5wKp_1zekKoh1FS9oveJ2qSvIN8fZ7xaoQ-jeX6SvPnGP5hfgKF-fpt8PQfOYEA440sbT-dqbZE3ZLnjNL6WNYq4G-QsL2j0dq0wnv5GpxeP_1ZlOnp8gKdIxgyGYvvf5WX54w9XOXyZmZWRdnAcGHz2ZhREXmhdYqkLFIcnFf8UdsmOvy3rfq3F7Su-M5Ryh0D3IzfcIMRlEGrCI2OzJWxkQP67QjfJ1o5R6Hlpwh1wCdMpTnxf0s-Scdl4NkGHDvx6fYUgPDOFBvlRSJivlnZt8cfRxSC26Lljsc6e1ZpSohZPowtdzatfJ3SyHd5HP2CNnwrvQLXF-IjQ-Nuuh2n8voGVC25Nia_0Ig0EQ.I6zApuSkF8RBezDE3PGSTw

```

### Challenge Response (Encryption Header):

```
{
  "alg": "ECDH-ES+A256KW",
  "enc": "A256GCM",
  "epk": {
    "kty": "EC",
    "x": "RAo3KxhGpt7yYxW_Tm8IAPox8x7cCFgc7yasrsOpJZA",
    "y": "Y7CNtyClsamk8ntn8irys2lhCSX3tAfm5LPl5TBjZ9U",
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
Location=https://<FQDN Server>/<TOKEN_ENDPOINT>
    ?code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjEzNTQ5ODI4fQ..WxiSpfV8eqSd0GM-.0n-72HKxzqFRwzx1Oc3DIg06WHg-2eIjKQPlWhPi8MssadiwRRrklCakwXxB87Z74D_RFAG3mtjaRIoQism_GH5BZgA_ktrw9WyFsZ0SHdRKxCY-DMGRRaNmoLtHM-HWHsxOGx71lQm-BGaxYXxkwsxUqddVl8Yy0ES7vlNUWKDbO1ISZd7nhS0sk1nbqVpXCWKk38voFJMYrtW7V_Yf_OVtTaFJa2PhBlmcDfx66vJYwR-c03zmcFqAujApA2UnHQJQ-W1-kXIAcn04BHLj7bmFR0BGKrVkrYvJMdxotM84qKYTY-Vc7e_7CsbXF4BXHAzInG-JmVGnuSsrA08-wAO2nMjlCg2-jXy6M9P6BUE-7O4zTYxvPurgKmUUHuCzlA3R9KXRlQJA4ULppClTkbsankZ8bWOIchv4bv79ZMHlshf5JzB9XFAboUHUcg0SV6pPIiidegof6TnrTw6BCep3Ma9JYSfuJiwmgfYdER7E80m4npAT_h0R4sze1O2suPPxb0PWXnxj2SvYTgypnNeKFFzfIIQKzboEGfFOTSTq3zC7vknT9IAZ7skS7jcT0HGwRuy71WQ4gSYgToi9wQqseAj_qOT5uDeQr1QRdi8oejUbEzML47nUrAQLyB4Jc3a610S7HMFOt_sKQDjehz0ahUqYPxIVCAjS3El2wsQEZuZeFBxokiFBYTfvjyiKdXK-pW3XYt_CUkJ7P0DLPsvmp2RK_NKhXnUP4FVirhfFaZ09ZZLxBVrElHeLD_zWhKpuhsO1ll3fqdXWpdmOdB4p26y_nZbNEx6MAUQd1hS7MT_rNE-Xf1bv5U6UQI4z5MuNRV1o30xJDwVnZbcGJWLY_YjQCo1pXignpSkVhGWa8pbbEGk0eUDtKQzsQF4NU9O8kWq9s_BU3hwqvBN20zT5R8fltRQG02oi_NYLKfaU3-yvo85ug-EvpYcXRxu_bLzgmiFmZvXLsb3Y_AyIVf-W1rPn5qIsXyU6NKRWwZjRjUMtsLJW3Plny8kasqqQkhTeLNiyuCABIeR-6aF8DO64TIndDTOroLDLEABgDmIwG9shaW0Oo6FKSyEkTfSjt-7KyY6a1pn4f0ZwT2AJvclX-jYFl7qrmwnIPyKmbRab-Ywf_o6GmRXKdsxpdSUoJ9F3UqmecgzG1FztcjlATcq4mVFTkxiChE9vi-f5RdPK1vbrIyE2sDdsVoZqTARE-qhvSS2CXTjIyAs8R3GFRw8XEU7X7DaudMR6mx7ijDOgccx5orc_zCj04y12-wUwm-Gp7PAXl-CCyzeQTe1pYbyfFs9BDZTXIgIu7k-VCRDhgNe-ta9Xjv3BJgzcKwWfRoCVzjU.iuwrMPyAYR3qVzlidbJFaw
    &sso_token=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjEzNTkyOTY4fQ..NR-rMXAjauh98AIt.BXMEJpyBdtcO0OVFK35g8LqFWdlHpQH6ZuomSaDRnylTfeZyg3MT-FSK2koDIZZZKVEq-lobi_7fRrvfiRQNGz4_6tmfqahpa-FC3ZZinMoopWr_9vY5obxDfBWSOFRu274mwxgFrikHkWxEGDwMG2u7BKU5zIvXNipDT5IxoTMAsbnUPeQuQNc8-uUKR4PC30xp_Waz_msckco3Yd4RJtb2nELpc_dc7nm5hpoaQ6-kVND2QnNBp_mQctPyo9Zcnmjra49oq_MU_9ij7KU2wId_eMMRdMiuQX5g57Iw_0TmUxYkP7JRf1Xlh4TxhfoLACVr3fOtzy6V_IU5mIWkxqkK8b5xXZC8VxQ7iL01ARSiYVxzBrmrOb56dOYPRcV9YdRwxKps1g2EFORoq5xGO-a3au78JtTH9MUnGKOx7grGkeG3LLc-Mf1N3vKFvjEdbDkwpmeqeNfte9Z2wW6MWolMYaQUsPq1gEz8sojjeaXl7QzPg1lIrJDdy96o4mQxlz43VEJEs4XcjpaMageuB1jNRPR8B5yanM5wGUmK-NqncSb45WHLDBa4pSsaMUlBqMO4nZY4MR_rBIvR4qntE9cxzLMdUP7V40fkMZG4MBIod18CjWnn-Rmwwg9eEAHw7uCwKbuSRQnEfMEnwq1V_LMjEsZXeYinWpA11WZF29rwrsClV9jmBd_8lqW0EIxhGHz_R5yZG92jAvs7vIaW-QifQTcygxZI8YOmBX2-sD53c6Vdr6KC3D9lEWA6c2uDHlOMvo284lcsgGGD240VfDCufba-yeBQjbppTtKC9O2yyF8gNRR83uVk4zPWI8OOCn7FnS7CEaDWJiJF74nMEttHN6nOBmirAPd9mxvWd2aISA9RvsrgMGbO75FVw4D8OXTTh9i9secA1AA57PcKdNqNqQDUVJlQqLpcdm6W7j1HCQzpJceClD7HXYdomaI2ZOdkQ72sPrERZfOIPGz6P0U2sIT_xv90xkurDxBo3pZGIYmF1vrb49gdjvP7UD7u5nD1VyYooyE60vGxhLM7IGTceI-B0iQi1Rx6JKNNi_erJFliKbZYcR61gLlR_QiM0nP87lPpMoPJp9iOqmxcqvLRvDASLPMD2DNS6VauSHPXhTbnpAScfvq0nwG5tV0s4y2lJDRTGBC4XQ3uIoDTMVCwqmoMHv3gDGmDhIbuV-FlWFL9eD0i0UT9ndcWYquWT6iCsfAqgbb75bVHSd3VOP2oMSTUT3UL7wrP9mJmG7cE_Ghtzj-oHh1FqQswCyPl-DVJoQNudiE4yqkxv2LhtCeFbZw1MfbJML0t-uXQ5sFSmy5IDOPUK-rxCPg7oS_YQ2BckkuYeYnnBa1IBuWcWb6nkAHYfZrJFEopylUgNkcZCH0AqP563pxjQv6NMhxJLN9cRog1uMRAmWXpe-N1ruUzGNvIAmS0TKFkKH7LojzWTmTPnOEQUWlIkvnXy_eA_cG-k5jtWjJOQ3h8ijhtMfSYTSSsXAIAmNL7Yru8P33x0Ahxd1M7Q2LbjJPazV0iAcbPOx1F0uLcTzDqGz2G_EyiPSHdixCb3g-8A6wmWKdbaAvV8_mz-JGKKe1qIPBjzeew6Ewj2dTA0BZetVqFm_wnYh3s-2tqiGZszsEhyAH-OA9I9teh2trAmc7RjYSQQDmW1YjNA9K0m4hjYi5BG0uFtGCTlC_zGrdzfTYLDTz5BGVNkazr5-rcUCiDZktcwYzJ9lCpWruFijtk5t-bbtSyYryRajUfF3t3_Egsm7wlU00oNJBveqRI4aKHyCL4y3PJj7czasGUK1o6v2-wQlRVAun_eYHzbS0ymzhnvAmPgZ1Ap39w0OpEvng5Y5casnSTaUM9-G5BYDQDOmfM05hjjHAVlbXlVqPtN4GA0KnylJcKujQO5Gtrpy0Gosdbr5lUP6GqMuB0vyiMUyrXR-iwp7rPfuiZIp9Dgy5-6PHfNeMIP4Z2X_HDjXS_27QLRlCfUURM74mgFfqbXdroeqUqcckVV_-NpCvv0udyflgSykiNizAcVWHk7UYxeGrZfnlDkkjJRGQEWwarbh5tiWuQtaxtruqORvC5FXmVAIYW9Hs0VNPEBaWgbLSpgOVlqnGxn-D6dY14M-6St9vxoNkQ-OtOvxnIOTL9KW8F2SJbZC9jP_h80MFwjlZLEeDJsgmCbgcOrDV1GEpSdd0cVaY1IgspIdqBuFs45TyvZkg7lFYjPEJ_XeN4ABbF5TYWfPtVUcH_xh6i1vWiFZJh9nQB7C2pjPjk3HS7rmlfQKn0UyJ7_3WKJk4CvN8dLSoRnkqr6GplHooINBhucki3g7XXH8O6c3D_yXfMynNmosZrAdsfBsE8M1WCOsSye2Li2KDomIhleQ0c_qR0jPfrmSZ-AkQaVYVYtf50_2OVcY6BwM36KOkPhRCf6Mf2YfW4_9-BukZUhmzT6LpJ20YelLuyG-17YZHDiPpIqTY0aBuKqmtB0avGYBCaw0oUxfpUkl5wS8mVgyJFBcYLIz4_bipqaWH6NNCVb24pO5GJg7yd6wkHyHvnjaaEhL43oWoij5gmuBDl9oUhtSfGFE5Di7BU2kX9GDlp4qhjSnq6JaaES0xEmbdpCdczafs_BZQ4CFb4zhswXpin1z-ZR47hnX6zH0jMQSay5WPpL5hbAgQM8kCK9VhXxCInGjbLfKOX0u6xg6ljv8nJtCJfmBgbZKN0xm6IeXfTwZOZavuUPSsWSN5o-gSmmdaGIKGywkEuQL6ziwVtE7iUJRERI-A328vuPWQFHIKV_3IidUTXl_EmUYjeoI24K0yNv1HUATg997-XidjWAOdyPJGzmaWY9UTNbbk.ThAsgW4o3Pb9poaNxb3zNg
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'UazzivrHoMGsMinyLFO4'>,
Content-Length=0,
Date=<Zeitpunkt der Antwort. Beispiel 'Wed, 17 Feb 2021 08:16:08 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


### Authorization Code (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 1 Minuten. Beispiel: '1613549828'>"
}
```


### Authorization Code (Decrypted):

```
{
  "alg": "BP256R1",
  "exp": "<Gültigkeit des Tokens von 1 Minuten. Beispiel: '1613549828'>",
  "typ": "JWT",
  "kid": "idpSig"
}
{
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'va4QyNmrg9R9rC01aDGJ'>",
  "code_challenge_method": "S256",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "token_type": "code",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: '6o2FRVBiSQdOslqQtBw4'>",
  "client_id": "eRezeptApp",
  "nbf": "<Der Token ist erst ab diesem Zeitpunkt gültig. Beispiel: '1613549768'>",
  "scope": "e-rezept openid",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1613549768'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'UazzivrHoMGsMinyLFO4'>",
  "exp": "<Gültigkeit des Tokens von 1 Minuten. Beispiel: '1613549828'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1613549768'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: TnbuPTLYhE-mQxSQHRDNn9xARlnLaEhNjZq8M5u_uuw>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '148417917973edaa'>"
}
```


### SSO Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1613592968'>"
}
```


### SSO Token (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1613592968'>",
  "kid": "idpSig"
}
{
  "nbf": "<Der Token ist erst ab diesem Zeitpunkt gültig. Beispiel: '1613549768'>",
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1613549768'>",
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
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1613592968'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1613549768'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>"
}
```


## Token Request 

```
https://<FQDN Server>/<TOKEN_ENDPOINT>
Multiparts:
client_id=eRezeptApp
code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjEzNTQ5ODI4fQ..WxiSpfV8eqSd0GM-.0n-72HKxzqFRwzx1Oc3DIg06WHg-2eIjKQPlWhPi8MssadiwRRrklCakwXxB87Z74D_RFAG3mtjaRIoQism_GH5BZgA_ktrw9WyFsZ0SHdRKxCY-DMGRRaNmoLtHM-HWHsxOGx71lQm-BGaxYXxkwsxUqddVl8Yy0ES7vlNUWKDbO1ISZd7nhS0sk1nbqVpXCWKk38voFJMYrtW7V_Yf_OVtTaFJa2PhBlmcDfx66vJYwR-c03zmcFqAujApA2UnHQJQ-W1-kXIAcn04BHLj7bmFR0BGKrVkrYvJMdxotM84qKYTY-Vc7e_7CsbXF4BXHAzInG-JmVGnuSsrA08-wAO2nMjlCg2-jXy6M9P6BUE-7O4zTYxvPurgKmUUHuCzlA3R9KXRlQJA4ULppClTkbsankZ8bWOIchv4bv79ZMHlshf5JzB9XFAboUHUcg0SV6pPIiidegof6TnrTw6BCep3Ma9JYSfuJiwmgfYdER7E80m4npAT_h0R4sze1O2suPPxb0PWXnxj2SvYTgypnNeKFFzfIIQKzboEGfFOTSTq3zC7vknT9IAZ7skS7jcT0HGwRuy71WQ4gSYgToi9wQqseAj_qOT5uDeQr1QRdi8oejUbEzML47nUrAQLyB4Jc3a610S7HMFOt_sKQDjehz0ahUqYPxIVCAjS3El2wsQEZuZeFBxokiFBYTfvjyiKdXK-pW3XYt_CUkJ7P0DLPsvmp2RK_NKhXnUP4FVirhfFaZ09ZZLxBVrElHeLD_zWhKpuhsO1ll3fqdXWpdmOdB4p26y_nZbNEx6MAUQd1hS7MT_rNE-Xf1bv5U6UQI4z5MuNRV1o30xJDwVnZbcGJWLY_YjQCo1pXignpSkVhGWa8pbbEGk0eUDtKQzsQF4NU9O8kWq9s_BU3hwqvBN20zT5R8fltRQG02oi_NYLKfaU3-yvo85ug-EvpYcXRxu_bLzgmiFmZvXLsb3Y_AyIVf-W1rPn5qIsXyU6NKRWwZjRjUMtsLJW3Plny8kasqqQkhTeLNiyuCABIeR-6aF8DO64TIndDTOroLDLEABgDmIwG9shaW0Oo6FKSyEkTfSjt-7KyY6a1pn4f0ZwT2AJvclX-jYFl7qrmwnIPyKmbRab-Ywf_o6GmRXKdsxpdSUoJ9F3UqmecgzG1FztcjlATcq4mVFTkxiChE9vi-f5RdPK1vbrIyE2sDdsVoZqTARE-qhvSS2CXTjIyAs8R3GFRw8XEU7X7DaudMR6mx7ijDOgccx5orc_zCj04y12-wUwm-Gp7PAXl-CCyzeQTe1pYbyfFs9BDZTXIgIu7k-VCRDhgNe-ta9Xjv3BJgzcKwWfRoCVzjU.iuwrMPyAYR3qVzlidbJFaw
grant_type=authorization_code
key_verifier=eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiUUp1QzVSZHlIMVJzbGZsTFNwdVdORG8xVUdmV3pJNnRjMFVIVGhWQWlROCIsInkiOiJBWXZ3RjdwTzlkb1R4WUR1akJpQkRsNUV4WUZFaG82a09lY0g5eElpS2M0IiwiY3J2IjoiQlAtMjU2In19.wLWFwuGzlRWl1T3mIBnRZX0cNJ2Z0HM0fjHBZSWOI4yjCbadgdOkDQ._ccIr2H41DQFzXX7.1O9aglSdqFc51EP3rHmT_Dh-LX5rpB52dc36Rgnxcc01DzZhrU8MnBOOKzdC6ySH_VaUPganHHcpm1mChw9VUpG19pT-ItIQMdirU7qCIH4GcXVi7bgfmlhjKWO0G0mYx5mq4gEfRmOGU3QUSt36Z9R__Njdu-gfgxI.pB0kwXFC46kJfXjwHRLdjw
redirect_uri=http://redirect.gematik.de/erezept

```

### Key verifier (Encryption Header):

```
{
  "alg": "ECDH-ES+A256KW",
  "enc": "A256GCM",
  "epk": {
    "kty": "EC",
    "x": "QJuC5RdyH1RslflLSpuWNDo1UGfWzI6tc0UHThVAiQ8",
    "y": "AYvwF7pO9doTxYDujBiBDl5ExYFEho6kOecH9xIiKc4",
    "crv": "BP-256"
  }
}
```


Key verifier (Body)


```
{
  "token_key": "VUtvbU93MHMwanZCN2ZkWG1lUG5vOFZocjFEakEyY28=",
  "code_verifier": "bWDMar78epMWI8yuDql_yCdckKpitLhHnQLzghRRN0I"
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
Date=<Zeitpunkt der Antwort. Beispiel 'Wed, 17 Feb 2021 08:16:08 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "expires_in": 300,
  "token_type": "Bearer",
  "id_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjEzNTUwMDY4fQ..Ha3eAjKvZpPuc3K1.RXch1ZCKqWEy9UfEN3BXKXAxBhghYGAQO18Pb1ea0gyuk__bIzZ_jYCtKXr3YtPgemCO7mKyrYavi8xOp-KrFkHm2HtcyiCl6-fk5gGLPliXYRcSQnMwJhpOq-20T2ElEBPqm6aeJRaQ0fZ5Xhb-OQc2d1iwfczQFgYr8iULf40LFlKfDbdtkgckoIR461qCN-dM5q3MdGUtu9hH4xVV-0W-G1uFQ0Yc6isrPvwz9ffiML8zznSMo_eVV1zzuCTreVGyEdie6ln2XBXp3EEaJIW3LkNKq8yM4ePn-28szJISIV7nPJi8TPIembAyVrJtDw9bpteDS7MkaB-rmtXUusT1QLgyBKLacZBPEbJYthgTABaN-VuMxJvR7hX7EGcg-wSdTFpMrp93K0NJcMYaehTjnsr1bRw6mHYARJaMDCn4qXEdLEnY3vlfioB25VytaP5X-YcO2Ifj7G3X7gJBAd8RTweTFqhBmXBRp8niqfIQ2VBJwQ5nWdiYMEPU229yTxCLlNIyE27VPDyATy6k2yu4GCVXl8FkZYUytp5HCtKP3wqZQS335c7Z0wPSrAm_H1PhRSS3FNCGof9MzeragnxjXFZxtlH26pjktXWu9rFDiUIPfkj8_nHgbZaYGHD-bCGifHw5vrQo_EyTAMsnCZrr4lzOAmCLBI5u3KEorGd5IcCyZBFqBjcrZh5cxl9N0DkqycjmlLh6AUOjQHzhe11fx6-C8z88KGfPdxb4p0Le29hinVV5-5Y6bxZFtQ09bgz8cdYOzf1eMoDpA_y3KS0hP8bHQcyCOHo1oy3uqm27CXWa4gXjwJ9d4sRiL2ib1pcDSBLwXUadxTSHha8Zq4JxDfAKPgH7Z-0bENKrZB5FvQfPsVw5nL2fUjcTA5zQxh0xzqbvERqz9zBCfWwEr7kNftraH3NIFxaEhrmNMj1q2SY5K7_rvmdQNxYrIE4IObADIFwmsEMJ_-fqUYRoZLH8U0wsrUxu3ofRUr6W8S3-17Q3_61FnKVyEKj5wTeak01GKsY7cLlD-ODI8_MjQJt6kP0qLpSHe5AQkSDl3RKYtgjL.lhSZsmMEXpxYSd6XaQCm0w",
  "access_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjEzNTUwMDY4fQ..xdsZi5ID4ufFmlFX.AR-iCeyJ6mRSmYmVnOOUhcD8ZQfhUiRDSQex4oY7XEwQPFFgBL9wLAmBHIVDoSHH9ILAhvwg7OQy0y4UynaSCs8TUQsDMB9luLsodDjRtiIvYJQ_MbCJ6BcQyPvvVIUxFea4Qam1S8C1bkPMH_O-uwXPSmE1i6H3IWDZafdzT30Hg7VT6RuhG7DKRNTF9JK_UsuSQByyikhkt-ss_sXoSAqlG_lnBhdof_PLfHaqPN-7TSoXIzMjLDsLFERcATlKr5RAm2X0TS2KMraz2Qln1P6BWdvCwXMnspp1MtqwWbh5MlWzY4vMdR24oRQMdNIOnP3kwDYof6VnfTixm-BruY0U_ryt0e6QwF1aAIXiahF9pW6KLY3E-Ue04ZayQ5s9_-XHqy3WD5GwKglLCEdMgIdKM75umZwZRIXaEKUSpAhAgHgKboCjPwTWsyAw7HQEwEuV0aM_aC2Yyk7qMLuhVwV1MXvZPcn-IrmkOFGmQMxQmBrojveAVZ0-ZzKe5lGavSnKsWu7nbzrKhUN4IVNox9InvxOxoLSaNc_UujsrgYzY-0CKnlwOTyDBvosu_dr-rJEM8RT3svoDh583wPNWRlUcOWnchl0YFGtlpXw-1NhG2dN5pcBTjhRdReExBy7uOBoKirKlZ3WdL3Urs3TWITuh_8NQp5HPXx--ucDfR61_Tcf6N9ibzuvWyyWrfBYgCkH8OsKRS_PYumehtg5RZ1dyS30lLvhWujV4bfhXhrkmTAjTfgtCso5x_k_Awl15NfLOLsE1RhuOyDIRVnhs3Q7VDUDqgxpSQ-AN80kT-pCm6wiMPWKA6uWEbQQ_NrU-cfTTAEID8WSUYbpGYQ2XapggizOdO6I8dI_F5ozM1j3g_dZJe4MvpUoZUpLJXZKnr_TcfyX9liuI3D9WdsRfccUWq8u_AIdR99hxUUGRMPcNDxc8bTZ9kuUVuz3auCxjrDMrtfQMIVSSrWrMxRJP65EF7eXS_zK4BAoUgSFwZt_DgcCsLyqgH-XuU-rmsf_EqXMnEtAATaxZNMZLxI0fKz5tQ2iUEPTJMqcynRtVmYwfOernB7ajFGOv9LUYw1PBR7jHvbKsBsaHZTO8gJ20TKAtDGNRKA8HcXWcEM.G9Z3CtvaJxHWUk6HmSnDyw"
}
```


### Access Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1613550068'>"
}
```


### Access Token (Decrypted):

```
{
  "alg": "BP256R1",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1613550068'>",
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
  "acr": "eidas-loa-high",
  "azp": "eRezeptApp",
  "scope": "e-rezept openid",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1613549768'>",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1613550068'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1613549768'>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: 'eaaf7c9bd29bacf1'>"
}
```


### ID Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1613550068'>"
}
```


### ID Token (Decrypted):

```
{
  "alg": "BP256R1",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1613550068'>",
  "typ": "JWT",
  "kid": "idpSig"
}
{
  "at_hash": "<Erste 16 Bytes des Hash des Authentication Tokens Base64(subarray(Sha256(authentication_token), 0, 16)). Beispiel: 'cHLbwloDPO7v7E+qyE42bA=='>",
  "sub": "<subject. Base64(sha256(audClaim + idNummerClaim + serverSubjectSalt)). Beispiel: 'qDAmiQOl5_rJ5-ok48lbjSs6QH9oya7VuxUJ-_E1HCw'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "amr": "["mfa", "sc", "pin"]",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: '6o2FRVBiSQdOslqQtBw4'>",
  "aud": "eRezeptApp",
  "acr": "eidas-loa-high",
  "azp": "eRezeptApp",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1613549768'>",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1613550068'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1613549768'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>"
}
```


# SSO Flow 
## Authorization Request 

```
https://<FQDN Server>/<AUTHORIZATION_ENDPOINT>
    ?client_id=eRezeptApp
    &response_type=code
    &redirect_uri=http://redirect.gematik.de/erezept
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'IItEg1rBi0ByTtYk1ZjK'>
    &code_challenge=<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: St4BNLgZDQpe_oHx_Xf6eOy3fNv0nM_8kP1b91Dk3bk>
    &code_challenge_method=S256
    &scope=e-rezept+openid
    &nonce=<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'gleet1znYrHEkFf5J7N0'>

```

## Authorization Response 

```
200
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Transfer-Encoding=chunked,
Date=<Zeitpunkt der Antwort. Beispiel 'Wed, 17 Feb 2021 08:16:08 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "challenge": {
    "rawString": "eyJhbGciOiJCUDI1NlIxIiwidHlwIjoiSldUIiwiZXhwIjoxNjEzNTQ5OTQ4fQ.eyJpc3MiOiJodHRwczovL2lkcC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwiZXhwIjoxNjEzNTQ5OTQ4LCJpYXQiOjE2MTM1NDk3NjgsInJlc3BvbnNlX3R5cGUiOiJjb2RlIiwic2NvcGUiOiJlLXJlemVwdCBvcGVuaWQiLCJjbGllbnRfaWQiOiJlUmV6ZXB0QXBwIiwic3RhdGUiOiJJSXRFZzFyQmkwQnlUdFlrMVpqSyIsInJlZGlyZWN0X3VyaSI6Imh0dHA6Ly9yZWRpcmVjdC5nZW1hdGlrLmRlL2VyZXplcHQiLCJjb2RlX2NoYWxsZW5nZV9tZXRob2QiOiJTMjU2IiwiY29kZV9jaGFsbGVuZ2UiOiJTdDRCTkxnWkRRcGVfb0h4X1hmNmVPeTNmTnYwbk1fOGtQMWI5MURrM2JrIiwidG9rZW5fdHlwZSI6ImNoYWxsZW5nZSIsIm5vbmNlIjoiZ2xlZXQxem5ZckhFa0ZmNUo3TjAiLCJzbmMiOiJUbTVUNWQvR0tPUXBPdXlXQzZ3RXQ1NGxxQ2ZvM281WTVSbCthY2dlSklVPSIsImp0aSI6IjQ4NzI3NzMxNWQ5MWE3ZDUifQ.Slhhl5s37S3Fxh3_zNhF1AT2NO3inMBdJYBpNzHhabBS40-S__Qj8nlco7czvVMvDKq4hIAqTWAUftf2S9gpfw"
  },
  "userConsent": [
    "GIVEN_NAME",
    "FAMILY_NAME",
    "ORGANIZATION_NAME",
    "PROFESSION_OID",
    "ID_NUMBER"
  ]
}
```


### Challenge Token:

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1613549948'>"
}
{
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1613549948'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1613549768'>",
  "response_type": "code",
  "scope": "e-rezept openid",
  "client_id": "eRezeptApp",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'IItEg1rBi0ByTtYk1ZjK'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "code_challenge_method": "S256",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: St4BNLgZDQpe_oHx_Xf6eOy3fNv0nM_8kP1b91Dk3bk>",
  "token_type": "challenge",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'gleet1znYrHEkFf5J7N0'>",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'Tm5T5d/GKOQpOuyWC6wEt54lqCfo3o5Y5Rl+acgeJIU='>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '487277315d91a7d5'>"
}
```


## Authentication Request 

```
https://<FQDN Server>/<SSO_ENDPOINT>
Multiparts:
sso_token=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjEzNTkyOTY4fQ..NR-rMXAjauh98AIt.BXMEJpyBdtcO0OVFK35g8LqFWdlHpQH6ZuomSaDRnylTfeZyg3MT-FSK2koDIZZZKVEq-lobi_7fRrvfiRQNGz4_6tmfqahpa-FC3ZZinMoopWr_9vY5obxDfBWSOFRu274mwxgFrikHkWxEGDwMG2u7BKU5zIvXNipDT5IxoTMAsbnUPeQuQNc8-uUKR4PC30xp_Waz_msckco3Yd4RJtb2nELpc_dc7nm5hpoaQ6-kVND2QnNBp_mQctPyo9Zcnmjra49oq_MU_9ij7KU2wId_eMMRdMiuQX5g57Iw_0TmUxYkP7JRf1Xlh4TxhfoLACVr3fOtzy6V_IU5mIWkxqkK8b5xXZC8VxQ7iL01ARSiYVxzBrmrOb56dOYPRcV9YdRwxKps1g2EFORoq5xGO-a3au78JtTH9MUnGKOx7grGkeG3LLc-Mf1N3vKFvjEdbDkwpmeqeNfte9Z2wW6MWolMYaQUsPq1gEz8sojjeaXl7QzPg1lIrJDdy96o4mQxlz43VEJEs4XcjpaMageuB1jNRPR8B5yanM5wGUmK-NqncSb45WHLDBa4pSsaMUlBqMO4nZY4MR_rBIvR4qntE9cxzLMdUP7V40fkMZG4MBIod18CjWnn-Rmwwg9eEAHw7uCwKbuSRQnEfMEnwq1V_LMjEsZXeYinWpA11WZF29rwrsClV9jmBd_8lqW0EIxhGHz_R5yZG92jAvs7vIaW-QifQTcygxZI8YOmBX2-sD53c6Vdr6KC3D9lEWA6c2uDHlOMvo284lcsgGGD240VfDCufba-yeBQjbppTtKC9O2yyF8gNRR83uVk4zPWI8OOCn7FnS7CEaDWJiJF74nMEttHN6nOBmirAPd9mxvWd2aISA9RvsrgMGbO75FVw4D8OXTTh9i9secA1AA57PcKdNqNqQDUVJlQqLpcdm6W7j1HCQzpJceClD7HXYdomaI2ZOdkQ72sPrERZfOIPGz6P0U2sIT_xv90xkurDxBo3pZGIYmF1vrb49gdjvP7UD7u5nD1VyYooyE60vGxhLM7IGTceI-B0iQi1Rx6JKNNi_erJFliKbZYcR61gLlR_QiM0nP87lPpMoPJp9iOqmxcqvLRvDASLPMD2DNS6VauSHPXhTbnpAScfvq0nwG5tV0s4y2lJDRTGBC4XQ3uIoDTMVCwqmoMHv3gDGmDhIbuV-FlWFL9eD0i0UT9ndcWYquWT6iCsfAqgbb75bVHSd3VOP2oMSTUT3UL7wrP9mJmG7cE_Ghtzj-oHh1FqQswCyPl-DVJoQNudiE4yqkxv2LhtCeFbZw1MfbJML0t-uXQ5sFSmy5IDOPUK-rxCPg7oS_YQ2BckkuYeYnnBa1IBuWcWb6nkAHYfZrJFEopylUgNkcZCH0AqP563pxjQv6NMhxJLN9cRog1uMRAmWXpe-N1ruUzGNvIAmS0TKFkKH7LojzWTmTPnOEQUWlIkvnXy_eA_cG-k5jtWjJOQ3h8ijhtMfSYTSSsXAIAmNL7Yru8P33x0Ahxd1M7Q2LbjJPazV0iAcbPOx1F0uLcTzDqGz2G_EyiPSHdixCb3g-8A6wmWKdbaAvV8_mz-JGKKe1qIPBjzeew6Ewj2dTA0BZetVqFm_wnYh3s-2tqiGZszsEhyAH-OA9I9teh2trAmc7RjYSQQDmW1YjNA9K0m4hjYi5BG0uFtGCTlC_zGrdzfTYLDTz5BGVNkazr5-rcUCiDZktcwYzJ9lCpWruFijtk5t-bbtSyYryRajUfF3t3_Egsm7wlU00oNJBveqRI4aKHyCL4y3PJj7czasGUK1o6v2-wQlRVAun_eYHzbS0ymzhnvAmPgZ1Ap39w0OpEvng5Y5casnSTaUM9-G5BYDQDOmfM05hjjHAVlbXlVqPtN4GA0KnylJcKujQO5Gtrpy0Gosdbr5lUP6GqMuB0vyiMUyrXR-iwp7rPfuiZIp9Dgy5-6PHfNeMIP4Z2X_HDjXS_27QLRlCfUURM74mgFfqbXdroeqUqcckVV_-NpCvv0udyflgSykiNizAcVWHk7UYxeGrZfnlDkkjJRGQEWwarbh5tiWuQtaxtruqORvC5FXmVAIYW9Hs0VNPEBaWgbLSpgOVlqnGxn-D6dY14M-6St9vxoNkQ-OtOvxnIOTL9KW8F2SJbZC9jP_h80MFwjlZLEeDJsgmCbgcOrDV1GEpSdd0cVaY1IgspIdqBuFs45TyvZkg7lFYjPEJ_XeN4ABbF5TYWfPtVUcH_xh6i1vWiFZJh9nQB7C2pjPjk3HS7rmlfQKn0UyJ7_3WKJk4CvN8dLSoRnkqr6GplHooINBhucki3g7XXH8O6c3D_yXfMynNmosZrAdsfBsE8M1WCOsSye2Li2KDomIhleQ0c_qR0jPfrmSZ-AkQaVYVYtf50_2OVcY6BwM36KOkPhRCf6Mf2YfW4_9-BukZUhmzT6LpJ20YelLuyG-17YZHDiPpIqTY0aBuKqmtB0avGYBCaw0oUxfpUkl5wS8mVgyJFBcYLIz4_bipqaWH6NNCVb24pO5GJg7yd6wkHyHvnjaaEhL43oWoij5gmuBDl9oUhtSfGFE5Di7BU2kX9GDlp4qhjSnq6JaaES0xEmbdpCdczafs_BZQ4CFb4zhswXpin1z-ZR47hnX6zH0jMQSay5WPpL5hbAgQM8kCK9VhXxCInGjbLfKOX0u6xg6ljv8nJtCJfmBgbZKN0xm6IeXfTwZOZavuUPSsWSN5o-gSmmdaGIKGywkEuQL6ziwVtE7iUJRERI-A328vuPWQFHIKV_3IidUTXl_EmUYjeoI24K0yNv1HUATg997-XidjWAOdyPJGzmaWY9UTNbbk.ThAsgW4o3Pb9poaNxb3zNg
unsigned_challenge=eyJhbGciOiJCUDI1NlIxIiwidHlwIjoiSldUIiwiZXhwIjoxNjEzNTQ5OTQ4fQ.eyJpc3MiOiJodHRwczovL2lkcC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwiZXhwIjoxNjEzNTQ5OTQ4LCJpYXQiOjE2MTM1NDk3NjgsInJlc3BvbnNlX3R5cGUiOiJjb2RlIiwic2NvcGUiOiJlLXJlemVwdCBvcGVuaWQiLCJjbGllbnRfaWQiOiJlUmV6ZXB0QXBwIiwic3RhdGUiOiJJSXRFZzFyQmkwQnlUdFlrMVpqSyIsInJlZGlyZWN0X3VyaSI6Imh0dHA6Ly9yZWRpcmVjdC5nZW1hdGlrLmRlL2VyZXplcHQiLCJjb2RlX2NoYWxsZW5nZV9tZXRob2QiOiJTMjU2IiwiY29kZV9jaGFsbGVuZ2UiOiJTdDRCTkxnWkRRcGVfb0h4X1hmNmVPeTNmTnYwbk1fOGtQMWI5MURrM2JrIiwidG9rZW5fdHlwZSI6ImNoYWxsZW5nZSIsIm5vbmNlIjoiZ2xlZXQxem5ZckhFa0ZmNUo3TjAiLCJzbmMiOiJUbTVUNWQvR0tPUXBPdXlXQzZ3RXQ1NGxxQ2ZvM281WTVSbCthY2dlSklVPSIsImp0aSI6IjQ4NzI3NzMxNWQ5MWE3ZDUifQ.Slhhl5s37S3Fxh3_zNhF1AT2NO3inMBdJYBpNzHhabBS40-S__Qj8nlco7czvVMvDKq4hIAqTWAUftf2S9gpfw

```

### SSO Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1613592968'>"
}
```


### SSO Token (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1613592968'>",
  "kid": "idpSig"
}
{
  "nbf": "<Der Token ist erst ab diesem Zeitpunkt gültig. Beispiel: '1613549768'>",
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1613549768'>",
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
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1613592968'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1613549768'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>"
}
```


### Unsigned Challenge:

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1613549948'>"
}
{
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1613549948'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1613549768'>",
  "response_type": "code",
  "scope": "e-rezept openid",
  "client_id": "eRezeptApp",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'IItEg1rBi0ByTtYk1ZjK'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "code_challenge_method": "S256",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: St4BNLgZDQpe_oHx_Xf6eOy3fNv0nM_8kP1b91Dk3bk>",
  "token_type": "challenge",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'gleet1znYrHEkFf5J7N0'>",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'Tm5T5d/GKOQpOuyWC6wEt54lqCfo3o5Y5Rl+acgeJIU='>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '487277315d91a7d5'>"
}
```


## Authentication Response 

```
302
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Location=https://<FQDN Server>/<TOKEN_ENDPOINT>
    ?code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjEzNTUzMzY4fQ..epkB5NXxl9wAJUOY.J0jakh3OqjfdbcaqqEFrGFUQd35UEsZtD02TS5CtQBc2ha6-enpCR33dFwFIHrz8KIXtBh22tZDnbucH9DfyMN3Un8rTofMEV7FwyvFWaHFoVoyCjvWPbObFJF2bLd4V0Ol1j3FKtj9qsmfpG1XcxA4lTT1WUih40xv9sO3m28doKOLWNgbRzaOHRarYDPRPnIz5N36pvqABFiXiFJYlg5PkTwFrlpsYVtvdPtjStEqMjPuBATK3FEPqdipv_3Th8BDNlx5lhs79WQ2Hr74Ssa-EF4HkAYyt-6OfwpcOQyqhLVmrQBhb1ShWSmcuaATLfWaxpF6hOTz91tj_1vdPavkdapmw780gRDG--av5N3LnsIf4MYBk9bigejCyg-D-fsB6PdAeOUZwxxfbG4VwFNLeYCQGpEX3WOljiPjrA37zvwRkuqhzJ5ghELCBy-QJ3rm9WAF1PP-RfzTjli5kM-0nKE0eevC5Kr3CiEtGcRXTgcQxU1Kiqjj9p_BLG3J7xTx7x-lQ2aF3aLEFKihrjVHmUJb-4sR4YTNRsLC7oI0BGV0RY6fjzmJMrtdP40_ZdzuMj9Mz0jAu5ntP5u5gthLwQboLIb807kA6oSS_juU9lloD5yOvvA53ngP6BW7RZvFz53B9Yn9KocWZvnlKr-llEyrX6K9dj7PTfoyfuGOgwCx_QZxfwK6Kxmo58UXgS2ToQYCTaiIqrtLN3wODrEYmDmIaQG_D7LLLIqUy6mf1LazESRwWEv3JKw1SNEHXBqBfq9wL-lDQTBZuFfT6f0e2g8ntSnpvrH1lftqhslE19-pUWeWAgNBPIbJvg9a63WV_5e9sZZ90IAZRr_gVeFOqLNm2XNOwmrVi5cqMzaT9wrkvnhBtEZ4JJ8KrmuVmt3UDXKg5bHmOiTSXmLCyeF5xNwDpnGw4mzVO8FSD2TFsLdyAYgujws0aMMtsnQhaKBQQRmCsxAffwHGXfBvP6ayeX9INJBrUAqXvrNXGYRWdFh2b-f91Liqt4Jf5sFK9rG15bAjj3MAPsDTQjPBJbwtQnxi9rtaPvm3JYf6ENwWLF7tkZpk4AOm-Xnal8_ZWt49Vo8jybcVwuJ7KOeDfhhg5NKx5y-yYTzIHcNzQJX5D9S7sS4deTu7ePjM9dbPPs4MXtZoK_Zo-9wvtsOXRD7o3Fb61epiJz7ZPQEeVtirKeLlHqCFJbKvfzPNWrC64P2VGninxaXFABZaGeu9ncHf4VTnr6jKimZaIgr-Xis-S1t2qUP5v3h9bGxw9QZLzVtmb6J-a22o.wIMaZRHOYQKZsfcN8Lvyaw
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'IItEg1rBi0ByTtYk1ZjK'>,
Content-Length=0,
Date=<Zeitpunkt der Antwort. Beispiel 'Wed, 17 Feb 2021 08:16:08 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


### Authorization Code (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 1 Stunden. Beispiel: '1613553368'>"
}
```


### Authorization Code (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "exp": "<Gültigkeit des Tokens von 1 Stunden. Beispiel: '1613553368'>",
  "kid": "idpSig"
}
{
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'Bbaf5AYKToVKFBaDDECk'>",
  "code_challenge_method": "S256",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "token_type": "code",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'gleet1znYrHEkFf5J7N0'>",
  "client_id": "eRezeptApp",
  "scope": "e-rezept openid",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1613549768'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'IItEg1rBi0ByTtYk1ZjK'>",
  "exp": "<Gültigkeit des Tokens von 1 Stunden. Beispiel: '1613553368'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: St4BNLgZDQpe_oHx_Xf6eOy3fNv0nM_8kP1b91Dk3bk>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '5c1f47eacca66ef8'>"
}
```


## Token Request 

```
https://<FQDN Server>/<TOKEN_ENDPOINT>
Multiparts:
client_id=eRezeptApp
code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjEzNTUzMzY4fQ..epkB5NXxl9wAJUOY.J0jakh3OqjfdbcaqqEFrGFUQd35UEsZtD02TS5CtQBc2ha6-enpCR33dFwFIHrz8KIXtBh22tZDnbucH9DfyMN3Un8rTofMEV7FwyvFWaHFoVoyCjvWPbObFJF2bLd4V0Ol1j3FKtj9qsmfpG1XcxA4lTT1WUih40xv9sO3m28doKOLWNgbRzaOHRarYDPRPnIz5N36pvqABFiXiFJYlg5PkTwFrlpsYVtvdPtjStEqMjPuBATK3FEPqdipv_3Th8BDNlx5lhs79WQ2Hr74Ssa-EF4HkAYyt-6OfwpcOQyqhLVmrQBhb1ShWSmcuaATLfWaxpF6hOTz91tj_1vdPavkdapmw780gRDG--av5N3LnsIf4MYBk9bigejCyg-D-fsB6PdAeOUZwxxfbG4VwFNLeYCQGpEX3WOljiPjrA37zvwRkuqhzJ5ghELCBy-QJ3rm9WAF1PP-RfzTjli5kM-0nKE0eevC5Kr3CiEtGcRXTgcQxU1Kiqjj9p_BLG3J7xTx7x-lQ2aF3aLEFKihrjVHmUJb-4sR4YTNRsLC7oI0BGV0RY6fjzmJMrtdP40_ZdzuMj9Mz0jAu5ntP5u5gthLwQboLIb807kA6oSS_juU9lloD5yOvvA53ngP6BW7RZvFz53B9Yn9KocWZvnlKr-llEyrX6K9dj7PTfoyfuGOgwCx_QZxfwK6Kxmo58UXgS2ToQYCTaiIqrtLN3wODrEYmDmIaQG_D7LLLIqUy6mf1LazESRwWEv3JKw1SNEHXBqBfq9wL-lDQTBZuFfT6f0e2g8ntSnpvrH1lftqhslE19-pUWeWAgNBPIbJvg9a63WV_5e9sZZ90IAZRr_gVeFOqLNm2XNOwmrVi5cqMzaT9wrkvnhBtEZ4JJ8KrmuVmt3UDXKg5bHmOiTSXmLCyeF5xNwDpnGw4mzVO8FSD2TFsLdyAYgujws0aMMtsnQhaKBQQRmCsxAffwHGXfBvP6ayeX9INJBrUAqXvrNXGYRWdFh2b-f91Liqt4Jf5sFK9rG15bAjj3MAPsDTQjPBJbwtQnxi9rtaPvm3JYf6ENwWLF7tkZpk4AOm-Xnal8_ZWt49Vo8jybcVwuJ7KOeDfhhg5NKx5y-yYTzIHcNzQJX5D9S7sS4deTu7ePjM9dbPPs4MXtZoK_Zo-9wvtsOXRD7o3Fb61epiJz7ZPQEeVtirKeLlHqCFJbKvfzPNWrC64P2VGninxaXFABZaGeu9ncHf4VTnr6jKimZaIgr-Xis-S1t2qUP5v3h9bGxw9QZLzVtmb6J-a22o.wIMaZRHOYQKZsfcN8Lvyaw
grant_type=authorization_code
key_verifier=eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiQ2QwaEdMNmVkMm1LQkZ3RVlqcUNQMlg0RlpZaDdMM3NST3lSVW1YMXBHayIsInkiOiJYMGdIZVZJRDczX29vb05wd1hqckNwVUFKTFBvbm50blVFUTd0MkJ6QWNvIiwiY3J2IjoiQlAtMjU2In19.XEQeiYTjmpGrrFe9E_MZPPS6Z7G4HvzLLKD-lXFbw5_nG2ovYIyDIA.jVvgDADdHdYLf80B.M4ShA9JvylPujVkkQlh0o1lREy7e94AWzP9xCS2i0lZi5M4nPSuXEh2vUPrAfszOdPJKer0PpVaY8geIiD-Hy0Ktk7raoluJj9F1vApB6rIR1nZrwTMmWOP_ugVEn1AQ8T2fS6TfB8O_PrdicH8YmkNPAn2zJrj1LMk.2v9Zdk0LipCWvGcVA_bLcw
redirect_uri=http://redirect.gematik.de/erezept

```

### Key verifier (Encryption Header):

```
{
  "alg": "ECDH-ES+A256KW",
  "enc": "A256GCM",
  "epk": {
    "kty": "EC",
    "x": "Cd0hGL6ed2mKBFwEYjqCP2X4FZYh7L3sROyRUmX1pGk",
    "y": "X0gHeVID73_oooNpwXjrCpUAJLPonntnUEQ7t2BzAco",
    "crv": "BP-256"
  }
}
```


Key verifier (Body)


```
{
  "token_key": "SXk4eHNSN1hUTmljSzlYbUlKREtZUmVjVFpuN1U0M1k=",
  "code_verifier": "Fj9R_YN-sxB13zvOfRGcfbEng2oewH57PyJv7K-v_5I"
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
Date=<Zeitpunkt der Antwort. Beispiel 'Wed, 17 Feb 2021 08:16:08 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "expires_in": 300,
  "token_type": "Bearer",
  "id_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjEzNTUwMDY4fQ..Xh59sEDEPF-9e6HW.e9uTgNEBvANui6msCtcpGWu3ETYt3qLrMMCnYYrJTkurhszSdjz-WbKD3KEt5VmWdGkp8Qg3-fNuIejN_xy38AtfYofF_4w9Ardsojj13VEyd-nR_YCkPC5LYmOE8YmEjilZ9kJnQhc6p5zPb6fDQq41V6cR-Cc_2C4sOYPmFDabHF4IHwAXC3XMHX1rzi7cJqP4BgXXVb9KIoxDbG7pP1Elac4KsEuSaQlIYIMhDTEkzBdekQE2ZrmR5AZpoYQpWIQO6rfHROqjCTFm9-eK3C3w0qDNCc1HFxSGmk8kEbmpoMTT2BloB-y3Y7MrngSgg4CakaeGCxPJgZ6zulIKsEuGM95j2zwiXlLHC2dXCEfvYlq680jL53ohSIMeOdu-PSbxdkXWaf6HOcOtSNjyW2_Yry0RTKYpTFVxoDUp9c9JnhUGmmMWO5kwUWum_ZSNneTGTr8ERnHGFzDC9PK8qSaDovu6VigAWQvuXmEmektiWda_jYNdGYzpdYEmJcmyzj9d9qR7DecCgf7lIKDEtKAIfES8Cm-fOvtEMrj-Z-nvyTxe7MPqV2FawmxAe2IksGIFvjrCg-7MTJmeygF39Tll75YKZiFl9_LwUSiATXZNpC8kzY3earju6h5YALn3f3lMoxWnzlBF-E16zUY-YIv0IBOaWpIdi-WLA_g0jpgcdWmU0QA4Rzc82397txXfAxkO4CmxMt00pE5Dmgi_fxS_08opjz_1e3Lawppw_23tvJv7-JQMdyzw4INbiYfatjSdtn1kLWRRn_JNlcmLpYNXlxYX4SIwBgfKINWS3cMlZMRLYbzUDZwHEkkFDnu95dJwQZPdzviBNCD5INAJ2Td2ay6VPg5dbzsUMndBS0QtdCKpipoOx1IFfBWoWRgsy6gC_GSZfshUs2FUxIPtb6lC_JNOY_SfNAMwz2EiElSJlSXb96ddB_vWMN3buulOa9I1FxUxIlyA73OBGGqaZEuDDQs7FAeo_zITsZL-7XUqni33r6rongJBQS7s6stIRu69a6sT36pMw3HpxJv8vlbB5q9kpJ_MKWqOwHNerUqeVSuo.TVu2ikdLXgs1jdyicX3JJQ",
  "access_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjEzNTUwMDY4fQ..P7tgMSK88mjyzfDe.ip5sCg8qZty0oR0dnWkCB8qQfSdq7XWIpYkDvOvlM8zoyaD1B0w7OFfVbNSH2JeTKtkLrqqwXgFSzKA-g45LFMIjpt4JrngBkMp55L63mss4GSSpSxY3FCMt8f9ytT9ifEbSy5Db6nwSqnQ-1DENstGULdlSowKQ6MyaVgOPajvDB1UOAmw_EyVrX94zgb1PASPWqNgqtCLnCyq_JF9m_un8x8AxqCLiAM_BQftsncsQqpx_eDsFVoW7hVxSjMRlzyAVNO2gAmgOUdpFexLXfbpecqx1XrcWrvKEs6JXrHu6WRCrdsql60rMOzkL4rtqW6uxk0YQvXJspldSFPJUrzMUb4EyeCJz-ZbcDo8Bz7PHlfRyiO79_aJsXqOqJbqYJOHozUvaHrGI3BhU6zgW5JRpoiPOGNXGw7NCm1HPyXvlB_GutTp-O-8WPKQgcHaq4RWSV0P8OCDXymv9I_XKhHXPB2zl8TG_bLI40pHXGHWBjHdEz503N6ZkRsQIVubfIuZF8OJy0SLeKZTBCSlrOMsizNJ_2ja5hFfiHMH-DodbyUexpnew-94ypWJZTREaycojeEv_wEJ5KLBpTnOuXjy9fueg2oKT73tdixbJ75vt_paZkDd9lLvjrgE0NTUCc7xpeq4rrEhRzG7JpC7OmNXRUp4oQGSlqR91W7UDB3aIJlIUboF46AOkD1j5MjnvUftR39GapDm5ruEbi1NWlgarwnYg7c17tsn7zhbMYHCb5u43CjV9lwyIfwYxekUDV9xXvK7-Mrvf_DCrWa1N89yaN6yWaEKbvYNPtxv8Y_Th1suyDHbOq_yg3T37-zRgO1v2s3ezFC70BP0BsgcjqAux5I2o0S_c-LlbCs2uKgCY5qYs-GUL-6V-RKqzwy7kFNUipVfITEc-25Jlc2F-bYciUdd67l4pwic5wsZRRvd6MnGjaluy0n9m6D4aYjuN5WQfw8A6hW4uerecFa7wdvEoQyNPF16bZw-CJcPG5WjhcfQ67TT2WCPq8rhSznFbZD4nuj63W9cACwQ7ELs4PjcvQxXuOUkOKZSpW0Qvv4wc703tqtkjejcIdVxpIccDGENeCcJxvkhY0FhiZcjaa6DkSk-C4IarzFzHSYA.yfEc4BECljO2iLUvg6kJJA"
}
```


### Access Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1613550068'>"
}
```


### Access Token (Decrypted):

```
{
  "alg": "BP256R1",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1613550068'>",
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
  "acr": "eidas-loa-high",
  "azp": "eRezeptApp",
  "scope": "e-rezept openid",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1613549768'>",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1613550068'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1613549768'>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: 'f371bd29a1b4e579'>"
}
```


### ID Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1613550068'>"
}
```


### ID Token (Decrypted):

```
{
  "alg": "BP256R1",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1613550068'>",
  "typ": "JWT",
  "kid": "idpSig"
}
{
  "at_hash": "<Erste 16 Bytes des Hash des Authentication Tokens Base64(subarray(Sha256(authentication_token), 0, 16)). Beispiel: 'DfnPdQp2zd122eD1qe9oGQ=='>",
  "sub": "<subject. Base64(sha256(audClaim + idNummerClaim + serverSubjectSalt)). Beispiel: 'qDAmiQOl5_rJ5-ok48lbjSs6QH9oya7VuxUJ-_E1HCw'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "amr": "["mfa", "sc", "pin"]",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'gleet1znYrHEkFf5J7N0'>",
  "aud": "eRezeptApp",
  "acr": "eidas-loa-high",
  "azp": "eRezeptApp",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1613549768'>",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1613550068'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1613549768'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>"
}
```


# Discovery Document 

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
  "alternative_authorization_endpoint": "http://localhost:55567/alt_response",
  "sso_endpoint": "<URL des Authorization Endpunkts.>",
  "pairing_endpoint": "http://localhost:55567/pairing",
  "token_endpoint": "<URL des Authorization Endpunkts.>",
  "uri_disc": "<URL des Discovery-Dokuments>",
  "issuer": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "jwks_uri": "<URL einer JWKS-Struktur mit allen vom Server verwendeten Schlüsseln>",
  "exp": "<Gültigkeit des Tokens von PT24H. Beispiel: '1613636168'>",
  "nbf": "<Der Token ist erst ab diesem Zeitpunkt gültig. Beispiel: '1613549768'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1613549768'>",
  "uri_puk_idp_enc": "http://localhost:55567/idpEnc/jwks.json",
  "uri_puk_idp_sig": "http://localhost:55567/ipdSig/jwks.json",
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


