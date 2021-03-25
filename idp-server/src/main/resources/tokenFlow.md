# Basic FLOW 
Log-In attempt using egk with DN 'CN=Juna Fuchs, GIVENNAME=Juna, SURNAME=Fuchs, OU=X114428530, OU=109500969, O=AOK Plus, C=DE'


## Authorization Request 

```
https://<FQDN Server>/<AUTHORIZATION_ENDPOINT>
    ?client_id=eRezeptApp
    &response_type=code
    &redirect_uri=http://redirect.gematik.de/erezept
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: '5uViKHH9VvVDqG7VbyuR'>
    &code_challenge=<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: fkCl2ruU6Ukwf37FNh5KMGoNHOAI2xcWzZlLLyyyXDY>
    &code_challenge_method=S256
    &scope=openid+e-rezept
    &nonce=<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'yoDAkY8meTsqqJZljsyM'>

```

## Authorization Response 

```
200
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Transfer-Encoding=chunked,
Date=<Zeitpunkt der Antwort. Beispiel 'Thu, 25 Mar 2021 14:27:16 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "challenge": {
    "rawString": "eyJhbGciOiJCUDI1NlIxIiwidHlwIjoiSldUIiwia2lkIjoicHVrX2lkcF9zaWcifQ.eyJpc3MiOiJodHRwczovL2lkcC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJzbmMiOiJGM3NsMG1VaFpCM3loanU3SjNMWEFqeXA4U2tycTNBeUxYUW04elluNE13IiwiY29kZV9jaGFsbGVuZ2VfbWV0aG9kIjoiUzI1NiIsInRva2VuX3R5cGUiOiJjaGFsbGVuZ2UiLCJub25jZSI6InlvREFrWThtZVRzcXFKWmxqc3lNIiwiY2xpZW50X2lkIjoiZVJlemVwdEFwcCIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0Iiwic3RhdGUiOiI1dVZpS0hIOVZ2VkRxRzdWYnl1UiIsInJlZGlyZWN0X3VyaSI6Imh0dHA6Ly9yZWRpcmVjdC5nZW1hdGlrLmRlL2VyZXplcHQiLCJleHAiOjE2MTY2ODI2MTYsImlhdCI6MTYxNjY4MjQzNiwiY29kZV9jaGFsbGVuZ2UiOiJma0NsMnJ1VTZVa3dmMzdGTmg1S01Hb05IT0FJMnhjV3pabExMeXl5WERZIiwianRpIjoiMDA1MWVhMjEyNzA5YTRhOCJ9.nT2_Xq4CAubzF0oq1H88h3LMLSZiegH4nx2LS_Bk29lc8VxAYqwISR68aPYarF9SdvpJ2ntXkz0xbdle5y-Gwg"
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
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'F3sl0mUhZB3yhju7J3LXAjyp8Skrq3AyLXQm8zYn4Mw'>",
  "code_challenge_method": "S256",
  "token_type": "challenge",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'yoDAkY8meTsqqJZljsyM'>",
  "client_id": "eRezeptApp",
  "scope": "openid e-rezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: '5uViKHH9VvVDqG7VbyuR'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1616682616'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1616682436'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: fkCl2ruU6Ukwf37FNh5KMGoNHOAI2xcWzZlLLyyyXDY>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '0051ea212709a4a8'>"
}
```


## Authentication Request 

```
https://<FQDN Server>/<AUTHORIZATION_ENDPOINT>
Multiparts:
signed_challenge=eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImV4cCI6MTYxNjY4MjYxNiwiY3R5IjoiSldUIiwiZXBrIjp7Imt0eSI6IkVDIiwieCI6IktkZkxvLVRBNXlhbG1oeDNoOEFfVW50RDRaaDhiQmRZeHBRcG5XRWFDZWsiLCJ5IjoiUXFyM0hOTXJrbGlBTFE5M3JBS1g2cFVqVF9nN0J3VVJnbzNLUlZ1Y3ZqUSIsImNydiI6IkJQLTI1NiJ9fQ..a0819FrvYmyWarbs.MYrieReBWB9FOhMTzPTwCX4BrmZy_CTzuPylBMOwWCgnrFrs0Un2zerRBMC3QptgqUx4JbVB-HQNnfv8izHPVG3lKu1R0T2oDYFtsw9dMqkPkiguQvDLbNViLvyDargq83nxP1QcC1z_oyUPK5RZvO6rVRZSlE56__CmG0rI-7Qr6qazz8GtdXdQjGj6Ri52qWXCAa1LnZP2Z3OsnWwJHngSmrSwb9jHfhJpZf7oY5G_MgCuXxLJqY8S7WpERuAZIEFynwJfBUvqs0WXXUYIyR9zVyahXCyhyjRGclNsg2kZzuxtwYeoGuOTYvgjWa5ZbF4-qVaeR37S3JvzUtVmK042N1bT1FEfvqnp3-BCpey1u-5yJr7AZ_g_goDcWpYHTkEmJrOKtOJvyqbYkYedJwtb--U2ue3p5SHu6MpQ_OPldS5F4tt43th_WcWC6hFUlzcycSvi-KZg-ZJ-ChVOl4_549GKqk8S9q1D8f3XiMoU_EiRzsbU-Wcx8KSkt5ewGKRQdccXa_2wxWm7yRLVHBdsvVuEcXlZquQiGcsC4LeLDhp-OOE8A5bXzHk0ztvJe5ZKTnaYxfcNqb-ojT8fIesErSfCWFzOBEzEWvx7vTXc7ma4ENfpP3yDxagxf1WPZyXxf11iNc3ndNQGADoYjSZk15LmvxPJDPgwAXfaIWdVljx41jdgJLh8v-3emzi1ww8AYnYMaJX2omonnAOgJBLtKayyhd98cd4gxvFceGZU4q8EZuf5uWvUPlmc6tlGe2x5zSliES6Z2abgWJqZ5evNqkKtcqxOhrupsHFSMqrL3heYbNe0z3LItXfyngMTme8H3aczj6dMmurIbr2lKqozjCyemxJ5IAD13iBxLQWJS-Kp4a5WnQt8m3oxz1dt7P0NAwslQ3AN3qGufPg7yvhi6dWO7A1BbQsz7XyoYoWENxvQuuadpcdPoU5jfa8JB31264zAyXY3fZDCLRPTshDRleYS-Bdmt83LvKe_cH-O38koT3ZqEGDOG-3uvQZN52O_eYAwIDBv82xYhpked3e78yXYtBUHC9L-5eXDQSHGk2yszIGK0EjKMt8Zw4IyiebRVUGWxkjGtBvjvFLDbMRW0QYFxDdbSCGS4k-h-xbCCHZ3LFvKIrVf14gKPCbA6LYdUsK7IZhiti0WMxy3riclZT36Ux7UhjLbS5RODfa-kL6jThsI3tX6URUQw9IOORoOrKMlhihayZKG54-CIfTT4Oaf3cPo8pUsXQF0rmYdBS47p9YWmt7_Xp3Wl6wrJoXPTd1OUk_jldgLKjE8zmtbadkCHXxwk8IjIp9_X99GtE3nNQwgWtuvXq9-58lWIGi25OUKgOKznH40zL8T3kvNNk2cxy10z3p5K3QHB_aOARuQbM3IMQ6xV5G9S94_TawJMBg-rxUQZJq4ih-P8ULaDYt1QZMXMMrHrAgB5L_j4DdcGVV5cHONxK1kKw9yXsy0B3fPIo7-erZ4jcsF4Q06qpbcqFHmB6WkdJrDb6ACJhxD6muDAY2J6LYL6THM_32rB7aSDjrBwJyDJ_cVxa756PCn3vh7y7vs5Jf_NVecdy2ZyAN-DO_SjgJuAPE5zh_t05-CPE8uBQjBFatNUOJQSWvS-tWse3jiaPGYDUkfq7l9kgD6GAoq1x3DmeBsO2A7J6pmZ1r_Uwjrw7rDU1mMDCyqxNUGgmwQLbpYAvkPM5DTh8mnpuGRbMzZfPKXiLQlvNa7A1Niq_xCvoS52xythDpynwaoxyEq0U6VCkuYlc5rY-OZ5uYTLfRujwVgFkjLdGgMAXp9WJSLA8pLtl5rA6-3wRZgviASKxCEmDgO8psEQ82Ap9WqMa1Ra2tFqoUayx_p3fq6tgAtZwZN6QmLwGrwRHlwrbxS5gAWyCBJn4DfhyW9QTprMFNfHEVcDUbkmfufAPCsTBaD2Pub7hodLDuZaDl82t4QGLey1ttZL1ZJRpVKMdcZhTCYf_KjxV084PcCmTqVsdh8BUrGHXd_V0eSJ2i1vUfO3Jx61hO6XYtN_eAJdOy3OrRvbUzBpU5Z9Op_Y-hqOBwysUBNyulzkwE8LCcrd7epRIBaooFkgGbk8m-pJ2sPSNPsK74s0pR_2_KbS8KFMBqk8hodlbXZ-fKC-WiU4ZGpMU2d6rIxvBFGwQckEkNXPWr2slNoxDeyBGZIM870Zwf-nb_gO7fghMmU50ailzkkq2eT32AoIC3lpFNYd6SHtNve5twCeJjbR-Jj5AcfRyDto3JHt3O4y_rWvzFEYfkQ35_WSO9vAuSBYzers42gdv0kN8A2Wl8HN3ojj6l3QFLwWGf6hsKokBIdeCTtMrOyRMMqHVROQ7-mZHiG4TfbLTDM6-iBCrF8v8eGN7T-mWoQra94NneY5A8cX5Srt972J8gVdeYTVXFzzQJahIvNHM_VUK-vtc7sTCGb2EG2gTYIkLtd_FRhlRMBhJZiVSsE9JAx4iZbTHUQyyQfWiZ-XiuZImPtYecd2_SE_z26RXG-fMpOauCrTMprMSuZRkrlhwxO3caJcW0EjJURKkP9yIZmlg8PR_9a4NyG8IvIC2Ufp2D2zFyNLpH98n3e6vKAyGHo07610boYxFrQlbeww72pvAPSEon2h8PCaKqx5KcTiri_rSCHetMfyBJ9vGo7_GrBIilY6J6IRCIqSal0I1qXB-vN22-SBIM1O-TUduX0icGjKmTIs4-4qV3V7wHMKljH6BXz2m2pnjqPqP4sLDCTExXz3jIXgMjbPmHaWkRxAtW-NY24A4zxCOmyYxbUU8ePrTmPoYs0QvovScgtpdZ4UxDdxk8HB9pQG7xiX6XDuDNzmaYI5yCsTCAf1GFl1Ds41B3LBCcxTmHinrlEjHbzITeVB1XEr-EsRjNvBMfP1xzUce2ztimFwD2WUvW3slBRWhJgHAJoUV_v1iUbT9WhBP2ImsNN2MXamjvvGgZFC2j8_UByzGC7Tqn-3VeoR8XJ1ENlTgO31TCqGeeHflY3Yx4XmoMTiBrMF4kIkB5rg4rQKxcQdaMEvhjR5hhYqr3pLJdXqYjzlkDItG_FAhHuvqrgdTrvsNwFbE3bEYZvT17RH_nAqhsffe2qqcp-7ROCcHCPBbqNnsuFL3JG-RHuUwrU7TVquqlMvx9T1j8Xryi5Y9k-kR_fVtzbDB9BEfC8LX0fmPdPTU_PNBpHubKAVEyuPtSPt-_N5LHQqNei6wRX3ii2Z5PliWG0mYNcBwABDXqRzqp2WRfY7prhGoJBmRPMA2K84QQKBIq_mMGk9ohX6_Ps-2EVJWt7vbPcY5jlQRakoGMToUCkkVDcEyMh7ESf-Q5Vjsc9engYg1ym3PVQ-rufZHhpT4jmgCmmUFmVgRczsEezUbIriA81Dkcn6MGvRMMpZgamf8FFc6B7ZhxdRsE_obUMdzTjHPyy8pECVEdNoAJsnvYE6cdL7d4sNU2DVT6yFdTJ.tTy5NyyIaTwKtKG_iNSKbQ

```

### Challenge Response (Encryption Header):

```
{
  "alg": "ECDH-ES",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1616682616'>",
  "cty": "JWT",
  "epk": {
    "kty": "EC",
    "x": "KdfLo-TA5yalmhx3h8A_UntD4Zh8bBdYxpQpnWEaCek",
    "y": "Qqr3HNMrkliALQ93rAKX6pUjT_g7BwURgo3KRVucvjQ",
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
    ?code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE2NjgyNDk3LCJjdHkiOiJKV1QifQ..h1HiBrmC11VO--fD.1oIrk2i2eAq91UcdW0gt5NqIYJ-YuhwQoKqoLr08WFP2ko6ddW9Vc5TosDOk7Kp2Vyr_dFWfdq9IleZFLpmCHPwhcI1R2cJ2H6ArAg0nT1muJWx5UvQRkd5orAA1zZIjIW_DjpM0LHHgOSrDvmONemiuX2SLBB3fvd4nUHXayNqjU4GaPj1J08bZuesvjJI6FbLSPdgNISRhoIKfAqqLVf94nZIHsZ-3YMvIoqYS94rkzI4gCsDgttkshRvHn1ZkpPTNnb3gU3_Y1ccukEewA1iNQhqHIqSUeQaJrhI4R74LqMripHCQvyRNDoFqBDXzFu1DPvYmm1LdKwjbNwYkPBIpzlFMsIs83FEjwIzuS6Q9F_LfEgOnpKTU-NyCsQEjUmRItV8n5DWH94b8NUMfPIuwy4AnKBAhn8tX9L13xSEQfHZkAZkaxydyyv3KV3do0hUD1321X1SgovbERjozA3JL6ope3jpHBO9Fp0KR2VgtXsXp4wtDO8Wwemda3lG19n2mxV9ai1R42aGqEAUSe5MHzJxodNfIQWzHiKEp0dRfVuDRwy7S1E_QLU9NcVH_zFP3R_C-qeIH9orGEvELVbKSHOQA3VpUCvhrgo8xNauzqDM9HrJN83SuZfoCMkkEe6xSfxn2IFFC0BqOgZJsa1M11OyMH75VFXk-4BPtT-xw1TW4M37nve6EUmExqLnVnoEDtKFku1WHGE436ajqbIVeUSuThRI3hTLl-V397aIompdZzAEs7iPVjsIX2nuaBQIeejeVDMywqTaK5X_LjZ-QdVCR96axvA14OhoARMEm9nSIa0ff6AbFMvEA7fDophm09LN8Zr6HBxH4dbw5mGwYwQXKKyXDg_xNL3WzWDzx9L_r2ezuNhuG-CZ1fylPcr1BP8qNg5Pn4YHC3ZOL8oyO6toEUFm48rud51j2kVyZaj-tmukeabbFkl4E-qPZODcKnAgp4kZCLE_6eo8VOn-OZHgCJv7yWxNBErLg6lhAJe3rR-fZ7fuft5atzNjC_KF-9QsAEYyWnVtHFK1NeCLDEsd83BaiGp1dtLMMsyRL0cETTbEURR1EElLu7gy1J8n96MOWtJ3_q8i4NWbzsoZbrO6_BgIL_dXCWLiIzjbATnWOurzSt1qPAQUtuDUIf-FvQiH5iKPIUBKvsBuwSnR-jz_FU26efLQydzJQks2XEFtlxtwiX3i0PHcj93wHZ3-c9wNboNXh4P-tBOEeuvJEgdiFIuE79utqTaaBrfay99KhxroQywUy3jUehbMHxYThYKHnpg.ATuhZGzf6a_85i_-TDW2yw
    &ssotoken=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE2NzI1NjM3LCJjdHkiOiJKV1QifQ..szHrXrFP5B771WuY._BJWazp0RP33bWadgT_YHDsjCfI0uHIdMorEz5b3jtx01Yi4KU3FnG_rOEHDxezw6IcBEvaRnt_WXCej1wpBqOJ7WLM3c7wP0suz5EKj_gflt4jGVWYL-jBh0vg6mOzVkBhk_0LH8APYjMcU4OhPKJ1z4sbimEF_jHfIztGHlMeVxi7KoLMO65PSVOKYBEpnfObIXctdcqqA32FbmA5f5LC9SdyU3iAC2b5ae3ff2-RDbEZjTr-CWQ-g4pPid7XtSzxaZLe4GlpOawgr37iBVmNF3NLq6cVzTAE7AXZNo3ky6SMs2PrFR4vRVcVoeJXdp9-2VvYzX_jBMwpGVst6tVVvxdPen5UbmjrcjRBb1RksLezKryKLmcHelVpnoP_uLRZTP32K6ifYZUUaYcSZGADsDgcfmY45PAB4Oi4DNDN8PQmXl9ol3RiID9DKxOJ3ML8X4ufxWmGfIaKy1mwRqbBJbb8gCjReAgSiDUGhbhk3951inDXQH0HEaoiQ3vwTP9O8nAh6XR-EH0ywf8M3Do6pIVqrOAogKC-j8bl0B4KPm3G2OJ72WBZrTcWKPfOGOp9GNlH-HoMRexVCZyv7xWDSyZdJ1BlSuyu7NrmUxXoP9Tkdj2DEPHRXdyaZzSUPHDnrwdKs-C17JOa3Fhve8yutrGT4N4Lvmj4d6W3V8QMjuRhXfZUl6HTr3Ts_W2GISvcV1ZSgGyhFZQPzkZ1mTqGDzMJVNiHkhzHONB8e5iFreGDdVO6IE7HQgx7llFrPRQT6Jd1y6yyuwp1GgjLythJ44tvrzcEykSPuW0JTwxvEP23g1rfN-nrS8xo60EoRg4Bod9CJiYZU9pPT-z_i33tmglecBzYCMMiq-C3YjRItA3pFZIhFr6na2qhrN7lNkDtf37bjHm5YWsU1pzexZDqq1ooTC0V6wfyba6-Jp9iW6ZhClJ8QThy9uvWiAI6WB40fKg5xsDgrNxMGwG6Zqiq1K1mQb5RA1bUt6XW-2Qpu2XTG-Jky9Ov_V5zFNQvS0Mls1s86-OAXPELOjlZ-mXg1AxJl2xrCnaNHEZOE8MnFY0hmvnU91qY3UfCyI831gvHkquBMEL9miOL3-oReje8K9jBWTQvUs8TFto7Cmb-t5utWM3dIPAbLko2G_6FxUXhXaN0RsKI_3DxOZ6oeTG_4o7NRgTnRnpbrN_q-Im6eXnOfpafilEreaY1ruMbLz1ewn-qo3hTNHC3qIN9kEfypz-Z8Solq0xq0KF9DTVsM4oPEd-eNMVf89kTfJt_kPutnehMp_mJrYSTSJi4q66JorkiLSJuQaVw9IVacUN7yet89_RvUiITIB5ETwGilg5-7y49Fu6LdqQLlkvpOYeW114Hh7w4xo1H55Omf12jNYxn79MMQEI2LJQ4ShA_cfyDbFWkRfF_hAC8xnFX54mL_Rh3_i4Cn3AsT0_lTiHKsgLkM7wP6RUxfbPTS93q0ZuRnyvwEuxoKYkiDWMKBHScZpV-aAyfKg7-ypWa9DmLP82eIyYXTUsB2AYcGWNMXGaKHnDauoqeFgOO30RGS06YZwpLl2nJfvErHam6hkXfEWt2FwaBObjBfHHcozzccBCAvqZFEpmxAP-YtUEk5GiTqXG57uAVYpp1fPqpOlfOQ7ZtuhwEAJPrkak3Qsu8csibyRvJy9vIcvX_YHwvwMPoam1BY3yXr0MSaDruiD90GnLxaE_4PT1UYb3DuX4L0Drjw7DKWaDNgTJFIDP2QgMFJLI4Il7fzGN6eTCCbmOzg6AZfFRLr7jqw8_XQMpNnP_oHnx0u0N_R69R0QaMAvqfgQ-QQqSW4E-1-hB5ZYqpW7_tUhxtmPlPLJuKX6NCc3_F77iuUiLZYXsrKyoadXaVTQ7azcjqIizoApWrqwKsu7CGkmKWrLBhUxuSOXnkPxXCnHzIsH2UzG3xvs2SA0K_faTKhqlVTaQAWTmWUnut8BVHtz6CP_UlPY6uYmmJislmpadSWGkAHHOuaAOtmwycxKFBfuW-FXFFxmbt3ran8q8Too9z-VQaitRJHVHqZpO0MaCNoxoX6noxXbxU5HqM2KiYDjhwIGSnY63e_ys5Xupbg_m2NJ4TNW2ywI58GRbnHEO_aOxkIwGedqWGkMIZ_mb-F2Pn8Mohg_ue0Lq5uzIId_NB5B89QLGCiRqywd5oZLPDDDyWQ6so991C-B-wSkbLzLKo4Dz631MhvSx8jvxOut0zqIL5N3qvraXoFcZG7Lfu7I-Nc1NvAk0vE3xBRd8IwjqMuIrCH3f7TtcPmafV-o60aYvSU6U9drGa19vvn5AoAAQStx5OFpKD4Z8-xNJ9dLFy_hJ-M-IiBY1VaOhxq1HGvN2tjdEcaKTdPseJrWMDGeq9hX2eGHVST1k_pSbwD28PoRzNhxwtJYjXxEeSCS4YOD0dOJvtMbm11FNsNW8R3vaAJlK75OJRaF0XI2ADBMLGAVyNESZgmn67RVMAPmbifyt18wrtcEDKsn9a2ZobagA0XcaJVA9wMGCcVXiBz35ybNmWlP_38anipgi8K3N7V4oI5srF3redb-jQ9QsYacZjrSlqCFHMXtORXPOMGW9ifrAgNXlR7m43H_EhG4N_YljJInKOjJzXM9imFb41FEk4Hk9Vo1QaxsDSjtwCVYPmAF2ExWTiEHtqudirlasjX6dA2zsgwaPD2cju-RB7_tcch47hyFXsICq6gcMOvWNUS5Oq2fOpk6hOdtTs9dzH770-Lb33LBT_a6OjFR4QfXMRhiUYBayfRv9fV-tI.SPKXO_JqH_n3XwSfOmIwug
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: '5uViKHH9VvVDqG7VbyuR'>,
Content-Length=0,
Date=<Zeitpunkt der Antwort. Beispiel 'Thu, 25 Mar 2021 14:27:16 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


### Authorization Code (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 1 Minuten. Beispiel: '1616682497'>",
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
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'CdB5sNxpZmo58o87tmqu'>",
  "code_challenge_method": "S256",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "token_type": "code",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'yoDAkY8meTsqqJZljsyM'>",
  "client_id": "eRezeptApp",
  "scope": "openid e-rezept",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1616682437'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: '5uViKHH9VvVDqG7VbyuR'>",
  "exp": "<Gültigkeit des Tokens von 1 Minuten. Beispiel: '1616682497'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1616682437'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: fkCl2ruU6Ukwf37FNh5KMGoNHOAI2xcWzZlLLyyyXDY>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '3990c5c8e0bcb26b'>"
}
```


### SSO Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1616725637'>",
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
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1616682437'>",
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
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1616725637'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1616682437'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>"
}
```


## Token Request 

```
https://<FQDN Server>/<TOKEN_ENDPOINT>
Multiparts:
client_id=eRezeptApp
code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE2NjgyNDk3LCJjdHkiOiJKV1QifQ..h1HiBrmC11VO--fD.1oIrk2i2eAq91UcdW0gt5NqIYJ-YuhwQoKqoLr08WFP2ko6ddW9Vc5TosDOk7Kp2Vyr_dFWfdq9IleZFLpmCHPwhcI1R2cJ2H6ArAg0nT1muJWx5UvQRkd5orAA1zZIjIW_DjpM0LHHgOSrDvmONemiuX2SLBB3fvd4nUHXayNqjU4GaPj1J08bZuesvjJI6FbLSPdgNISRhoIKfAqqLVf94nZIHsZ-3YMvIoqYS94rkzI4gCsDgttkshRvHn1ZkpPTNnb3gU3_Y1ccukEewA1iNQhqHIqSUeQaJrhI4R74LqMripHCQvyRNDoFqBDXzFu1DPvYmm1LdKwjbNwYkPBIpzlFMsIs83FEjwIzuS6Q9F_LfEgOnpKTU-NyCsQEjUmRItV8n5DWH94b8NUMfPIuwy4AnKBAhn8tX9L13xSEQfHZkAZkaxydyyv3KV3do0hUD1321X1SgovbERjozA3JL6ope3jpHBO9Fp0KR2VgtXsXp4wtDO8Wwemda3lG19n2mxV9ai1R42aGqEAUSe5MHzJxodNfIQWzHiKEp0dRfVuDRwy7S1E_QLU9NcVH_zFP3R_C-qeIH9orGEvELVbKSHOQA3VpUCvhrgo8xNauzqDM9HrJN83SuZfoCMkkEe6xSfxn2IFFC0BqOgZJsa1M11OyMH75VFXk-4BPtT-xw1TW4M37nve6EUmExqLnVnoEDtKFku1WHGE436ajqbIVeUSuThRI3hTLl-V397aIompdZzAEs7iPVjsIX2nuaBQIeejeVDMywqTaK5X_LjZ-QdVCR96axvA14OhoARMEm9nSIa0ff6AbFMvEA7fDophm09LN8Zr6HBxH4dbw5mGwYwQXKKyXDg_xNL3WzWDzx9L_r2ezuNhuG-CZ1fylPcr1BP8qNg5Pn4YHC3ZOL8oyO6toEUFm48rud51j2kVyZaj-tmukeabbFkl4E-qPZODcKnAgp4kZCLE_6eo8VOn-OZHgCJv7yWxNBErLg6lhAJe3rR-fZ7fuft5atzNjC_KF-9QsAEYyWnVtHFK1NeCLDEsd83BaiGp1dtLMMsyRL0cETTbEURR1EElLu7gy1J8n96MOWtJ3_q8i4NWbzsoZbrO6_BgIL_dXCWLiIzjbATnWOurzSt1qPAQUtuDUIf-FvQiH5iKPIUBKvsBuwSnR-jz_FU26efLQydzJQks2XEFtlxtwiX3i0PHcj93wHZ3-c9wNboNXh4P-tBOEeuvJEgdiFIuE79utqTaaBrfay99KhxroQywUy3jUehbMHxYThYKHnpg.ATuhZGzf6a_85i_-TDW2yw
grant_type=authorization_code
key_verifier=eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImN0eSI6IkpTT04iLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiWVE4TkszUmlBSGJKbzRweXRxNENFdmd1S3VPbm9tRzlNS3ByRVJ0OXp1RSIsInkiOiJwdVhyVWhBXzhSNFNOT0loeDNQS05pRFhIcEFrTVZ1THRpODQ2LUlnWXFjIiwiY3J2IjoiQlAtMjU2In19..tCPG9652bPMluV4X.skadBBewv_MYyas4r1x54IPizeU1UZGdLPPOxRAKiNLVSHbO6LKYmBx-85RTUjgJRrkIe1BDxg2xnxL8Ic-hhpcX_3hpR4ZjbeTa2K8zcNZ4Sq0_acLSVTqdeIpP-orZKLbiCQHoQm3aMkOQBGSDbtl2AnbCarS8jA.zDa6ctK-C4er4AtXOMDVYg
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
    "x": "YQ8NK3RiAHbJo4pytq4CEvguKuOnomG9MKprERt9zuE",
    "y": "puXrUhA_8R4SNOIhx3PKNiDXHpAkMVuLti846-IgYqc",
    "crv": "BP-256"
  }
}
```


Key verifier (Body)


```
{
  "token_key": "T3ZVeHZ2eVI1OFg4Vm85bXJLQWY0ZTBDaU1LbEtuTTM",
  "code_verifier": "AE3gUi6e5WXRZqwje6I3nzqJ7aR7FpdaA3Fv4inXk9U"
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
Date=<Zeitpunkt der Antwort. Beispiel 'Thu, 25 Mar 2021 14:27:16 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "expires_in": 300,
  "token_type": "Bearer",
  "id_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE2NjgyNzM3LCJjdHkiOiJKV1QifQ..WDIkTsqb6uotk8S6.AhItCuscSfN-j4A9zQ1hRb_HEd5kt2m5gVFDHmRpwzlRyNxeDu7eQexzeoOxn5H6_2FTfZ2-hYXJ2f_cy8ppvLm5cQKawpcLi3YUdby9VbSZqTFnyfi0ijXPhAZJqv2jP_3ERJ9_yjvDPFdWy6NJSHsTs_8r-83Xktgfjufeq205kiPbHHYU9sqe1d_ZPJC93dgp5BxBEulvkPiWmuIK-90l7JGXnpFnDPZ5yYeWMvSAEVfK_0sPKgeZGNpCUsCkcmme3UUx9iPoUwffcvbBrR4jaK3BbiuGoRqiMFRVLlWN4O2YwYK1g4jIPIDcQjBfNMh0-qcXc-XElyabMWpEXW9bMFz3X7lhV6OrsNrMwiX_ThfWdxepDfFxOgtdhvEAwVqXDVwQGCwY5Lm8i8XBoygZrZFrJE2Qid9hqX-trCTWqZsgI9O8vFMj8BBD29Pd_iM6uqP9W3JLKoQhbJHETU-Iq-f8nF_D_ovx3BohKwCEJfEyJqnmQTKgPhS_7KaM8C-jNbEV9JoYUzXqqeD0HPMeleOg8cIAivuCnxOnP-KiQ5LEtSD4KebpPQJRLc6dlzumc_phBra2RSLIiy0p2xhro-n0pLvJdeR1FXsBsShHpePMYRTtZBVMijPyMMmFrEp7L3eD1S_7rIapmIjM_YqTSYMK60sfmwzgPDzqtgsDuZOPNCg6wiSTeD9pW3XUoF8CEPr91YIqJnGhkUDZfaMgVfDNaP69-UBrz8fu-jtiaNRDJaasjvUXkuslz08grtFtc_2GkTg9YmlG8rPMwl4FJDVjrrQa3_nRE9on5XzorS8r7BULJShlNFs8j9SxBR1CXWi5vZVtK9wk8_GdSn1W8JZnsYi2wU6lx22fVhFB3fkDzhr1FXYL86FMRYNfhr6Nn-_WxILWDsMHAWpnEOrJ1_k6DYRvfnRFGA4Oy1JV98idfHlpi0YibckJE447dTtyFpR83uHIs8RPKSj9HkpmuNewnL2xoW0TW8yf6DVbvrOrh-v8x4DHd8UgKW47EduvJWVDWV8743QRc2k1AtAlar9sQpkjoBGIIMSUnL0YDIg58-c6AMdmCw.7awQ_2W1iTcZBZPlMwSPXQ",
  "access_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE2NjgyNzM3LCJjdHkiOiJKV1QifQ..VxmaO3L91IibBe7i.t6rZ-5KqmJO5-drEE8eMPujE3KwMyXjbzXlb8mdL5G8LePYRkjcwvl9kOpasIdzOk4vrMeXfMe_TjtB8FETN3ijb0ddK2FlA6146jWORRH2B8wXq9kOsgn4LvFDMm54x3T4TnZS6RvVFFzEuWqvE4OCYh2AL6aKoWCa4wsC31LaCm4UiCbPLXJKRjz_d6uz5mT7PyV7VAyi0L0I26bnhaaVcsc9ivjsz3crNWmZSuuBXsUvXn4HSb6EJfDxmKdbu5DrvztXU9jcNUmYbAEl4GvmIOyTMW4wr6urPW4hlGgL_gSrVoZZrY1rOvoQtju-DlXJtyFa6SE9ZvcbfogsFRh4NAF73SKm1xQPItoQihDXzWTyaZ0AC2CgMCtCaWWkuTKN3dss80GHfctVSirPvHQg3fT3ifX9CH_DTU537Twp04kxrwcsicrtuo7IosGC8GVq4gtXlDWy5Gsu-uU8AI14A7zXwBDB-Rezr4b2VW7X2Qk-2Sep2nBkGyaw9BQthDq5JL2QZGbNHaLiBgNvj7r4-gI6qcU-7pERvcs8IKwwNDPvjqXNPwc586mO9eduIA1ix-zhVXYlJpKfSwztvRJEVbM09P1OWGReERW7uiz5pFEF1XSTj2p3cpc8STS5bd7dggdd7qPyd6IBALx9qyioW_T3MLFCg-kOerXANJbiMq8mqsJeHRoOPp7bb6BWwtk_L8_gqeV-u0YnRi00EWopkWc1FCmcvYGRX-DpBCqE-S_Be9fi3aCpm3bca4coxLSWqhXbxPoGYd4ViiJNu6ppN9q6UKyjJ-QeaVYd5babcFl1AhLsqPwJpj_yBVscTBnhOvGBTrtPS7nFnT65IKiOH7SYfAo8L0llFil_zcJQ0koXEB9EgobYy6Oktl5yxVAlqgz_jYw4Wf00lugInBL5ATTYD7vfLejoIzixK-GdA9235gLtsoWG07VdlAl5tC5mxpvmrR70tDCH7-dM8QMRipRxwHMztIgpNOOAUZnklIOtibz3w1sWrZJrWzCMJNtGheensc-W_GZnF1PsfzyYTo2YpV8WeJ4ebWu3GRD38-IwzwxHGtMbSu7Hq4iPhv5txeG0.Tsk9fmw5fOtWjXihhIZZHA"
}
```


### Access Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1616682737'>",
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
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1616682437'>",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1616682737'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1616682437'>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '9c799e7f55e0100e'>"
}
```


### ID Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1616682737'>",
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
  "at_hash": "<Erste 16 Bytes des Hash des Authentication Tokens Base64(subarray(Sha256(authentication_token), 0, 16)). Beispiel: 'dJdAoiKGezKSt2UhMIw41A'>",
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
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'yoDAkY8meTsqqJZljsyM'>",
  "aud": "eRezeptApp",
  "acr": "gematik-ehealth-loa-high",
  "azp": "eRezeptApp",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1616682437'>",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1616682737'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1616682437'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '5c790de50a9541b2'>"
}
```


# SSO Flow 
## Authorization Request 

```
https://<FQDN Server>/<AUTHORIZATION_ENDPOINT>
    ?client_id=eRezeptApp
    &response_type=code
    &redirect_uri=http://redirect.gematik.de/erezept
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'S6sLGBIBzgFD7pZtylXe'>
    &code_challenge=<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: 3ruhJK8dBdJ0MMWU8GBFgVXp6Q9TlYjeQME6yZqMt5k>
    &code_challenge_method=S256
    &scope=openid+e-rezept
    &nonce=<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'kDDs9BuInrJDfkxramxl'>

```

## Authorization Response 

```
200
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Transfer-Encoding=chunked,
Date=<Zeitpunkt der Antwort. Beispiel 'Thu, 25 Mar 2021 14:27:16 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "challenge": {
    "rawString": "eyJhbGciOiJCUDI1NlIxIiwidHlwIjoiSldUIiwia2lkIjoicHVrX2lkcF9zaWcifQ.eyJpc3MiOiJodHRwczovL2lkcC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJzbmMiOiJ5WHBoWmtEa1lEVS1qMEdKamFISXRlTGl3YXFDaHJITDlSVUJLbmJ1SWtFIiwiY29kZV9jaGFsbGVuZ2VfbWV0aG9kIjoiUzI1NiIsInRva2VuX3R5cGUiOiJjaGFsbGVuZ2UiLCJub25jZSI6ImtERHM5QnVJbnJKRGZreHJhbXhsIiwiY2xpZW50X2lkIjoiZVJlemVwdEFwcCIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0Iiwic3RhdGUiOiJTNnNMR0JJQnpnRkQ3cFp0eWxYZSIsInJlZGlyZWN0X3VyaSI6Imh0dHA6Ly9yZWRpcmVjdC5nZW1hdGlrLmRlL2VyZXplcHQiLCJleHAiOjE2MTY2ODI2MTcsImlhdCI6MTYxNjY4MjQzNywiY29kZV9jaGFsbGVuZ2UiOiIzcnVoSks4ZEJkSjBNTVdVOEdCRmdWWHA2UTlUbFlqZVFNRTZ5WnFNdDVrIiwianRpIjoiYzI1ZTVjYmQ2MzAzYTBiNiJ9.mk2PUHFReuTKBQFzQ0DNWVhl-9WpRyWOMpSIoBJEJRs3XTF8kvHWQWIbnnNe-_EEoDU4YDhICgPJspq-1tMcXQ"
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
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'yXphZkDkYDU-j0GJjaHIteLiwaqChrHL9RUBKnbuIkE'>",
  "code_challenge_method": "S256",
  "token_type": "challenge",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'kDDs9BuInrJDfkxramxl'>",
  "client_id": "eRezeptApp",
  "scope": "openid e-rezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'S6sLGBIBzgFD7pZtylXe'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1616682617'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1616682437'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: 3ruhJK8dBdJ0MMWU8GBFgVXp6Q9TlYjeQME6yZqMt5k>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: 'c25e5cbd6303a0b6'>"
}
```


## Authentication Request 

```
https://<FQDN Server>/<SSO_ENDPOINT>
Multiparts:
ssotoken=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE2NzI1NjM3LCJjdHkiOiJKV1QifQ..szHrXrFP5B771WuY._BJWazp0RP33bWadgT_YHDsjCfI0uHIdMorEz5b3jtx01Yi4KU3FnG_rOEHDxezw6IcBEvaRnt_WXCej1wpBqOJ7WLM3c7wP0suz5EKj_gflt4jGVWYL-jBh0vg6mOzVkBhk_0LH8APYjMcU4OhPKJ1z4sbimEF_jHfIztGHlMeVxi7KoLMO65PSVOKYBEpnfObIXctdcqqA32FbmA5f5LC9SdyU3iAC2b5ae3ff2-RDbEZjTr-CWQ-g4pPid7XtSzxaZLe4GlpOawgr37iBVmNF3NLq6cVzTAE7AXZNo3ky6SMs2PrFR4vRVcVoeJXdp9-2VvYzX_jBMwpGVst6tVVvxdPen5UbmjrcjRBb1RksLezKryKLmcHelVpnoP_uLRZTP32K6ifYZUUaYcSZGADsDgcfmY45PAB4Oi4DNDN8PQmXl9ol3RiID9DKxOJ3ML8X4ufxWmGfIaKy1mwRqbBJbb8gCjReAgSiDUGhbhk3951inDXQH0HEaoiQ3vwTP9O8nAh6XR-EH0ywf8M3Do6pIVqrOAogKC-j8bl0B4KPm3G2OJ72WBZrTcWKPfOGOp9GNlH-HoMRexVCZyv7xWDSyZdJ1BlSuyu7NrmUxXoP9Tkdj2DEPHRXdyaZzSUPHDnrwdKs-C17JOa3Fhve8yutrGT4N4Lvmj4d6W3V8QMjuRhXfZUl6HTr3Ts_W2GISvcV1ZSgGyhFZQPzkZ1mTqGDzMJVNiHkhzHONB8e5iFreGDdVO6IE7HQgx7llFrPRQT6Jd1y6yyuwp1GgjLythJ44tvrzcEykSPuW0JTwxvEP23g1rfN-nrS8xo60EoRg4Bod9CJiYZU9pPT-z_i33tmglecBzYCMMiq-C3YjRItA3pFZIhFr6na2qhrN7lNkDtf37bjHm5YWsU1pzexZDqq1ooTC0V6wfyba6-Jp9iW6ZhClJ8QThy9uvWiAI6WB40fKg5xsDgrNxMGwG6Zqiq1K1mQb5RA1bUt6XW-2Qpu2XTG-Jky9Ov_V5zFNQvS0Mls1s86-OAXPELOjlZ-mXg1AxJl2xrCnaNHEZOE8MnFY0hmvnU91qY3UfCyI831gvHkquBMEL9miOL3-oReje8K9jBWTQvUs8TFto7Cmb-t5utWM3dIPAbLko2G_6FxUXhXaN0RsKI_3DxOZ6oeTG_4o7NRgTnRnpbrN_q-Im6eXnOfpafilEreaY1ruMbLz1ewn-qo3hTNHC3qIN9kEfypz-Z8Solq0xq0KF9DTVsM4oPEd-eNMVf89kTfJt_kPutnehMp_mJrYSTSJi4q66JorkiLSJuQaVw9IVacUN7yet89_RvUiITIB5ETwGilg5-7y49Fu6LdqQLlkvpOYeW114Hh7w4xo1H55Omf12jNYxn79MMQEI2LJQ4ShA_cfyDbFWkRfF_hAC8xnFX54mL_Rh3_i4Cn3AsT0_lTiHKsgLkM7wP6RUxfbPTS93q0ZuRnyvwEuxoKYkiDWMKBHScZpV-aAyfKg7-ypWa9DmLP82eIyYXTUsB2AYcGWNMXGaKHnDauoqeFgOO30RGS06YZwpLl2nJfvErHam6hkXfEWt2FwaBObjBfHHcozzccBCAvqZFEpmxAP-YtUEk5GiTqXG57uAVYpp1fPqpOlfOQ7ZtuhwEAJPrkak3Qsu8csibyRvJy9vIcvX_YHwvwMPoam1BY3yXr0MSaDruiD90GnLxaE_4PT1UYb3DuX4L0Drjw7DKWaDNgTJFIDP2QgMFJLI4Il7fzGN6eTCCbmOzg6AZfFRLr7jqw8_XQMpNnP_oHnx0u0N_R69R0QaMAvqfgQ-QQqSW4E-1-hB5ZYqpW7_tUhxtmPlPLJuKX6NCc3_F77iuUiLZYXsrKyoadXaVTQ7azcjqIizoApWrqwKsu7CGkmKWrLBhUxuSOXnkPxXCnHzIsH2UzG3xvs2SA0K_faTKhqlVTaQAWTmWUnut8BVHtz6CP_UlPY6uYmmJislmpadSWGkAHHOuaAOtmwycxKFBfuW-FXFFxmbt3ran8q8Too9z-VQaitRJHVHqZpO0MaCNoxoX6noxXbxU5HqM2KiYDjhwIGSnY63e_ys5Xupbg_m2NJ4TNW2ywI58GRbnHEO_aOxkIwGedqWGkMIZ_mb-F2Pn8Mohg_ue0Lq5uzIId_NB5B89QLGCiRqywd5oZLPDDDyWQ6so991C-B-wSkbLzLKo4Dz631MhvSx8jvxOut0zqIL5N3qvraXoFcZG7Lfu7I-Nc1NvAk0vE3xBRd8IwjqMuIrCH3f7TtcPmafV-o60aYvSU6U9drGa19vvn5AoAAQStx5OFpKD4Z8-xNJ9dLFy_hJ-M-IiBY1VaOhxq1HGvN2tjdEcaKTdPseJrWMDGeq9hX2eGHVST1k_pSbwD28PoRzNhxwtJYjXxEeSCS4YOD0dOJvtMbm11FNsNW8R3vaAJlK75OJRaF0XI2ADBMLGAVyNESZgmn67RVMAPmbifyt18wrtcEDKsn9a2ZobagA0XcaJVA9wMGCcVXiBz35ybNmWlP_38anipgi8K3N7V4oI5srF3redb-jQ9QsYacZjrSlqCFHMXtORXPOMGW9ifrAgNXlR7m43H_EhG4N_YljJInKOjJzXM9imFb41FEk4Hk9Vo1QaxsDSjtwCVYPmAF2ExWTiEHtqudirlasjX6dA2zsgwaPD2cju-RB7_tcch47hyFXsICq6gcMOvWNUS5Oq2fOpk6hOdtTs9dzH770-Lb33LBT_a6OjFR4QfXMRhiUYBayfRv9fV-tI.SPKXO_JqH_n3XwSfOmIwug
unsigned_challenge=eyJhbGciOiJCUDI1NlIxIiwidHlwIjoiSldUIiwia2lkIjoicHVrX2lkcF9zaWcifQ.eyJpc3MiOiJodHRwczovL2lkcC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJzbmMiOiJ5WHBoWmtEa1lEVS1qMEdKamFISXRlTGl3YXFDaHJITDlSVUJLbmJ1SWtFIiwiY29kZV9jaGFsbGVuZ2VfbWV0aG9kIjoiUzI1NiIsInRva2VuX3R5cGUiOiJjaGFsbGVuZ2UiLCJub25jZSI6ImtERHM5QnVJbnJKRGZreHJhbXhsIiwiY2xpZW50X2lkIjoiZVJlemVwdEFwcCIsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0Iiwic3RhdGUiOiJTNnNMR0JJQnpnRkQ3cFp0eWxYZSIsInJlZGlyZWN0X3VyaSI6Imh0dHA6Ly9yZWRpcmVjdC5nZW1hdGlrLmRlL2VyZXplcHQiLCJleHAiOjE2MTY2ODI2MTcsImlhdCI6MTYxNjY4MjQzNywiY29kZV9jaGFsbGVuZ2UiOiIzcnVoSks4ZEJkSjBNTVdVOEdCRmdWWHA2UTlUbFlqZVFNRTZ5WnFNdDVrIiwianRpIjoiYzI1ZTVjYmQ2MzAzYTBiNiJ9.mk2PUHFReuTKBQFzQ0DNWVhl-9WpRyWOMpSIoBJEJRs3XTF8kvHWQWIbnnNe-_EEoDU4YDhICgPJspq-1tMcXQ

```

### SSO Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1616725637'>",
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
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1616682437'>",
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
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1616725637'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1616682437'>",
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
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'yXphZkDkYDU-j0GJjaHIteLiwaqChrHL9RUBKnbuIkE'>",
  "code_challenge_method": "S256",
  "token_type": "challenge",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'kDDs9BuInrJDfkxramxl'>",
  "client_id": "eRezeptApp",
  "scope": "openid e-rezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'S6sLGBIBzgFD7pZtylXe'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1616682617'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1616682437'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: 3ruhJK8dBdJ0MMWU8GBFgVXp6Q9TlYjeQME6yZqMt5k>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: 'c25e5cbd6303a0b6'>"
}
```


## Authentication Response 

```
302
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Location=https://<FQDN Server>//erezept
    ?code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE2Njg2MDM3LCJjdHkiOiJKV1QifQ..pIQkl30KlujmigL2.H0hRzuHjXrdmmjUDlN8V-PAYzLhhDlUR4gbUgF0EbxlyVsUXrSJTKHLJDjOpnG0VCerk470dgayM8SnCig2fmUxOiCumbpBb8eHNRJNS9pFbQw2HCFrlUJjr8IAT4zLKyOD_DXHr0iPOi3-qn5bV77mg4aAyFYOBvxaI6ANJ7oNH10ITeC90T7OrpFAYnizmy_D8mrSi68fhVVEVsjknP4FKtU2Sl_i9749zV6AYBKVwIygmOCQYIrezqwYIsF5XlaIRiIJfnIl5cm1fuCIt4EtHdEF_SnxkAf3LjDlt9X9G_vhjbppAfN3j_IIJSqRDcPjCNw4knJ--oHEjQCBNkIre8-NTpWzM6jOAPKmUdAi5XM3rqF4uODRNK9aKS2stTJOKAxzQ6iCIvTUGkQ-KJVKR9P3CMJG7h2wiOjqy0fQ0XdtBwzeMIIaBi-6TfVayd6tMj1R9ThFztvkNn-XkDV4L5H9DuDVkdbk2t4uGqS5LDunhR1eUqE880-oG19JchtZCgeTNL8ut6Ala9cR6GI4famEi65HSVXW-3VKZAalZQbyTyRidGDTX204k-6D7PbGaUDDv_Of3i34AYoNSh8vCdDIZYJZk3-n5BvLmDc_ezVCbigs3JB3hLykA2xszt9ZinhksySJ2K1mYRz7fk3b9t-Oh76Uh8c4RzlTWb6llhsnIjTApC3IMzxlDYIititzKlDCrWtT0TvpTY2Y4Azlhbqd7NYH_e_ubkKeW2Ai3XPO9jfzYPI5Ky_Zf5RWFiCqaGlZwIZx1_ZycPU3wnoe-FL-7L5jsfGCfImLvEAQpeRGKD6S259CcRZ1betZD2oF1Wudj_pNI1kALXT-skrlDk5vsouPJv7wxR3-F3naNvdohmJbo7R7nfdcmoILAuoWAbmn1Q3lzJL8TNV3QVdZpPLU_-JTQf1IVpPD2nbvJNKQx3_b9m-pHs1fTl1gPtil1D-ot2RSLf29rGkW6RwCH5WxmI8ENKjbttOIgS2jEpFKXek55PFkQq828G1Hc0_jbp-mZjkGiFV3dLtXWoIvnK2_-aucRB7CJGNNtEG5PSa8k6KsU6LnbA7SmYpAeHMJ0dVIt2D4caUBmusF3zy0NJfpV7CKdZX90yAEvNZlQhXadTlUWJLhOeXgs-c0uGT2pifnZJdOJY9_ReYfYDnGwdix5sG4zQXdguMcQbmCQbNec4U1L72MiiC-8870ZZ3ofbYn36FbcONDvqzXQY9YIejJ_ykRannP84d5vnBFCz_BJ3-drs6AUmwRBS5ou_0LYZgh_NA.GIr-PHJSayP0jyKXDUiBmA
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'S6sLGBIBzgFD7pZtylXe'>,
Content-Length=0,
Date=<Zeitpunkt der Antwort. Beispiel 'Thu, 25 Mar 2021 14:27:16 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


### Authorization Code (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 1 Stunden. Beispiel: '1616686037'>",
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
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'jO7JpEPe51QMMXMqxf2A'>",
  "code_challenge_method": "S256",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "token_type": "code",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'kDDs9BuInrJDfkxramxl'>",
  "client_id": "eRezeptApp",
  "scope": "openid e-rezept",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1616682437'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'S6sLGBIBzgFD7pZtylXe'>",
  "exp": "<Gültigkeit des Tokens von 1 Stunden. Beispiel: '1616686037'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1616682437'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: 3ruhJK8dBdJ0MMWU8GBFgVXp6Q9TlYjeQME6yZqMt5k>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '8938e8850e3e183e'>"
}
```


## Token Request 

```
https://<FQDN Server>/<TOKEN_ENDPOINT>
Multiparts:
client_id=eRezeptApp
code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE2Njg2MDM3LCJjdHkiOiJKV1QifQ..pIQkl30KlujmigL2.H0hRzuHjXrdmmjUDlN8V-PAYzLhhDlUR4gbUgF0EbxlyVsUXrSJTKHLJDjOpnG0VCerk470dgayM8SnCig2fmUxOiCumbpBb8eHNRJNS9pFbQw2HCFrlUJjr8IAT4zLKyOD_DXHr0iPOi3-qn5bV77mg4aAyFYOBvxaI6ANJ7oNH10ITeC90T7OrpFAYnizmy_D8mrSi68fhVVEVsjknP4FKtU2Sl_i9749zV6AYBKVwIygmOCQYIrezqwYIsF5XlaIRiIJfnIl5cm1fuCIt4EtHdEF_SnxkAf3LjDlt9X9G_vhjbppAfN3j_IIJSqRDcPjCNw4knJ--oHEjQCBNkIre8-NTpWzM6jOAPKmUdAi5XM3rqF4uODRNK9aKS2stTJOKAxzQ6iCIvTUGkQ-KJVKR9P3CMJG7h2wiOjqy0fQ0XdtBwzeMIIaBi-6TfVayd6tMj1R9ThFztvkNn-XkDV4L5H9DuDVkdbk2t4uGqS5LDunhR1eUqE880-oG19JchtZCgeTNL8ut6Ala9cR6GI4famEi65HSVXW-3VKZAalZQbyTyRidGDTX204k-6D7PbGaUDDv_Of3i34AYoNSh8vCdDIZYJZk3-n5BvLmDc_ezVCbigs3JB3hLykA2xszt9ZinhksySJ2K1mYRz7fk3b9t-Oh76Uh8c4RzlTWb6llhsnIjTApC3IMzxlDYIititzKlDCrWtT0TvpTY2Y4Azlhbqd7NYH_e_ubkKeW2Ai3XPO9jfzYPI5Ky_Zf5RWFiCqaGlZwIZx1_ZycPU3wnoe-FL-7L5jsfGCfImLvEAQpeRGKD6S259CcRZ1betZD2oF1Wudj_pNI1kALXT-skrlDk5vsouPJv7wxR3-F3naNvdohmJbo7R7nfdcmoILAuoWAbmn1Q3lzJL8TNV3QVdZpPLU_-JTQf1IVpPD2nbvJNKQx3_b9m-pHs1fTl1gPtil1D-ot2RSLf29rGkW6RwCH5WxmI8ENKjbttOIgS2jEpFKXek55PFkQq828G1Hc0_jbp-mZjkGiFV3dLtXWoIvnK2_-aucRB7CJGNNtEG5PSa8k6KsU6LnbA7SmYpAeHMJ0dVIt2D4caUBmusF3zy0NJfpV7CKdZX90yAEvNZlQhXadTlUWJLhOeXgs-c0uGT2pifnZJdOJY9_ReYfYDnGwdix5sG4zQXdguMcQbmCQbNec4U1L72MiiC-8870ZZ3ofbYn36FbcONDvqzXQY9YIejJ_ykRannP84d5vnBFCz_BJ3-drs6AUmwRBS5ou_0LYZgh_NA.GIr-PHJSayP0jyKXDUiBmA
grant_type=authorization_code
key_verifier=eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImN0eSI6IkpTT04iLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiRXVZSkFHYnA2ckRiTGVzUExpSGRETzZnc1lESks3eVZiXy1tcmhFVFRRayIsInkiOiJSYXQ3cjg2Y1p3ZWJRVllCdzdzTGI4YXc2dkNGVEsxeUN1NVI3Mm93c0Z3IiwiY3J2IjoiQlAtMjU2In19..Ioq1H8bGSpSMEDyN.GkU_eH276E_93SpW5E3kNS0B1xcTjI3jmMEJOi8k73fw9nsvOidcm4oH4rboET6D-CdwIWLZYbW9OmBaaL9xFZnLamxi8GWrUjlQnSvXj0l2CZPDOJJDtXGZWhfctX2C0i1ekd7jUg_kLggNe6NojVxOShA7qkOA8A.yvBmpv5F0g3G392-omcOFg
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
    "x": "EuYJAGbp6rDbLesPLiHdDO6gsYDJK7yVb_-mrhETTQk",
    "y": "Rat7r86cZwebQVYBw7sLb8aw6vCFTK1yCu5R72owsFw",
    "crv": "BP-256"
  }
}
```


Key verifier (Body)


```
{
  "token_key": "V1FmekpXcEp3ZHVXVmV2Rm1QM3huWmg3YVc1ZVRsekQ",
  "code_verifier": "cjF9iJwrgEzgR7UN0NA_dSaeCd9XTfPvpyTTP3aLbq4"
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
Date=<Zeitpunkt der Antwort. Beispiel 'Thu, 25 Mar 2021 14:27:16 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "expires_in": 300,
  "token_type": "Bearer",
  "id_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE2NjgyNzM3LCJjdHkiOiJKV1QifQ..7IxaYdDZHmGMXu_7.AhdzONd0qEuSyU7k-9SpvUv1OoRrCbBsTjfNiFiIXDWfjc__h4nlSUw0gyUnUG1L4d2KP1jIoD4xIKiUpjnRq3rCjKSTPTb5OX5ARyDAkRtzfRdCFqcLVEuUCJP57XdrdxjL2b1v849KZz_WvbPYhUQ3-eOyvDgzzCzIP2KRE8vcHlkd9Ez1F2MUh_czMlng_A6bbWI3VddNbji2kdw8JlDlEFonQ0QDlQKs_T2bcBuRqGK0YCwgtkN4V8ehX1JwgJmFmVuyxZ23sCtQOkTpxuTx7d1N_kjCERc62QHRx1BdgtrN14JXx5IH404LNHlbOwvxosNiuenLSCeeONa0AbYldWbGlITa6rqnfxD3g6NAh19IB3tMyG_fF37esNqn5a_s7i-HrrehHU1sEVx_WlQmUvSxJhNQPkryvLPy0V3HZccIX6iLNjDdRjC9hDpY5XcsO7G2n_54Uqpl01QQxYMa-wmaxG15e_DuSG67WYftIkpyia5OMqgBP0ar3RDeVoXUqaGW6gInlQfKvc50aFsPvpaJMRSNY2onH-wx2ayFuW8dxRPvritc6LAHnVjUD8Vp_xAJhZ6TmTPIAgbN3tq1BJ6LiDd8DkCgUb--YIs0qjSnuKVufEVKnK__15FT5v0H0MZgT0Eyph2dzm8qLfZ_g7Ga1g1AA06gMHObOPLeTESnG7qt6jfCkeJ5Kim60YvCd73gZOES7-QAVg8_ZxIjCRzd9aPOrfV4Fcn5Hg9OhcaVTtMgn-NJwatO8NPwIwAAjEsZ3G17SsjHDcps2QR_BZkhjnCBoH2l5wA_iGTAJjuZDhmiQ43iQDKPaLFm73pVUIvNIIFTsyPayPYnqmvhEOl4kUcBQppcCGNbmDGxu_Bld_2TRBGG1yeZIjFhBd861_lCjbTLyqLAq_6oYjQ9joTeBYcr0QchHaiBsSBhyQd55Ys5b6_mHPMi1yG5pGMBnsA2h7QysQZyGV1hXcvCBEAQWcuPlmC5jDgDYYesmJhy2yfEBvyYmEfY85ILUoAxZq7oTGWCbkHKYsAQyYRLAhNS8ZiilxnHYn4Yl_ZSNCcUs72Y_x4kOA.0obnqM9MGgwlQJPj1wA39g",
  "access_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE2NjgyNzM3LCJjdHkiOiJKV1QifQ..qw_3sLJ4WUy9wg64.7z3o3cLl0Xy-96OzPwXbyFY-hBxcc1-AGmIYJ6htbHogewEOGh3Jp1Tar5DpdXHu1PDBqSe8fv9dJxm1OLbH1bNQpbouF4bU4IZ6nUAaHOgKDqEjCd7DoJ4rOPuVW3SMozbvOp2D8BP1ouMoXNmDT8T-i-aCUmM_L4xs0X0ST0V2A7eLU1bj7bcl-QACTIB45pBmsxI3Xg2gETdhzz5EJOHtmgnANJueHRhvVG-5Yige71d3inmjzkNyg5hGCuBtgp1fVYdXOsgk5QwAPm02MRHLZ0jHz7RqASV_2wqeyHJrHOAt7dWc7K9cRXyUTXc_cvbVrHzWNuTFX3tOAee7K1gRL7Tvl876J_s0_EXtCgEFaGjmRrYbLVbtCUsbMg-dzLxUb35Dyc7NdNckqyT8LoRMPgm8iZS1sTDG17-Yzi1iCqPLfcQ2KyIXdNnpqaES9B80KrkD61jsXMYW4lo7c3IXQfdK37v3TACk2YQDwLX8-vMQHL7Sbeqx5UC8k593DLPo2iQ2qrMwNhZo1EzE-dc1ioPRruLc_0X0oWNViPu-1BnVMyfyap0tdV-auAVn9tOYhw6FTxD79jyok8GwUyeRSpuH1noXgltxsPHlapYY9nQx2ZYcnMDZAmwm3CUcUG40mfN_zXVYkm3Ig5AXRJCHhAygjxJbql5l9r8BKpzgaAV_dvS_xkjtH2lTERhsOrC1ZYlBL0CdHCaQTjtM9-MEZLbM_Dq-KHGJsamhF_KNVWrRMaRybryo8XgvDnu-WjQboCzpDDwvNBwQBxmm_NEIxJdjyeoBLmkYYWb2kVDZMa-_-NpKoDnsueV6bwppV5D2bVRRLQ9Gf2vzCrHeR_rISjSczZpQWAWl9Lm_Lcv_di71Zb4GtOQLh9yvWedYHiqFX0e14CHhZyaQp79fuWAG6Gdxdo7KPmAY2Z48mIQoTet4WT76th_KUDHyHzBD_b5PvFG9g38-6n7MEtXa0JYSTVKLpN0LWd-gMoywY3n2U6crFrzQcSHAQfX7kwVP681RjSKCpAJehJkxxw48IBppKGL3LZKLveSfwmE0RcxmWKOyxwr-fLg-UaAic_fpjFxcWls.hei7w_1pUUmg8Cl8xNfq4Q"
}
```


### Access Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1616682737'>",
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
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1616682437'>",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1616682737'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1616682437'>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '5a95ff8d7fb1a916'>"
}
```


### ID Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1616682737'>",
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
  "at_hash": "<Erste 16 Bytes des Hash des Authentication Tokens Base64(subarray(Sha256(authentication_token), 0, 16)). Beispiel: 'YyAEnKIxaOvuc4CQrJjqtw'>",
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
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'kDDs9BuInrJDfkxramxl'>",
  "aud": "eRezeptApp",
  "acr": "gematik-ehealth-loa-high",
  "azp": "eRezeptApp",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1616682437'>",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1616682737'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1616682437'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: 'd033e133ae7aed1d'>"
}
```


# Discovery Document 
## http://localhost:53152/discoveryDocument 

```
200
Cache-Control=max-age=300,
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Content-Length=2678,
Date=<Zeitpunkt der Antwort. Beispiel 'Thu, 25 Mar 2021 14:27:16 GMT'>,
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
  "auth_pair_endpoint": "http://localhost:53152/alt_response",
  "sso_endpoint": "<URL des Authorization Endpunkts.>",
  "uri_pair": "http://localhost:53152/pairings",
  "token_endpoint": "<URL des Authorization Endpunkts.>",
  "uri_disc": "<URL des Discovery-Dokuments>",
  "issuer": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "jwks_uri": "<URL einer JWKS-Struktur mit allen vom Server verwendeten Schlüsseln>",
  "exp": "<Gültigkeit des Tokens von PT24H. Beispiel: '1616768837'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1616682437'>",
  "uri_puk_idp_enc": "http://localhost:53152/idpEnc/jwks.json",
  "uri_puk_idp_sig": "http://localhost:53152/ipdSig/jwks.json",
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
## http://localhost:53152/jwks 

```
200
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Transfer-Encoding=chunked,
Date=<Zeitpunkt der Antwort. Beispiel 'Thu, 25 Mar 2021 14:27:16 GMT'>,
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


