# Basic FLOW 
Log-In attempt using egk with DN 'CN=Juna Fuchs, GIVENNAME=Juna, SURNAME=Fuchs, OU=X114428530, OU=109500969, O=AOK Plus, C=DE'


## Authorization Request 

```
https://<FQDN Server>/<AUTHORIZATION_ENDPOINT>
    ?client_id=eRezeptApp
    &response_type=code
    &redirect_uri=http://redirect.gematik.de/erezept
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'iUFFOjFbPY9TTgbeiJIc'>
    &code_challenge=<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: dNXfkjcsNCu2xX50b0q-AQ29UazUKtFxJkvmniPdY6c>
    &code_challenge_method=S256
    &scope=openid+e-rezept
    &nonce=<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'UC1UMO24gXIBb3xnkMVg'>

```

## Authorization Response 

```
200
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Transfer-Encoding=chunked,
Date=<Zeitpunkt der Antwort. Beispiel 'Fri, 12 Mar 2021 08:46:02 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "challenge": {
    "rawString": "eyJhbGciOiJCUDI1NlIxIiwiZXhwIjoxNjE1NTM4OTQyLCJ0eXAiOiJKV1QiLCJraWQiOiJpZHBTaWcifQ.eyJpc3MiOiJodHRwczovL2lkcC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJzbmMiOiJxRXdaWGtVa3p2TFdsUVFtS2hocTFmNHFkYW9EcURtYWdUWUx3LWs3U01FPSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJ0b2tlbl90eXBlIjoiY2hhbGxlbmdlIiwibm9uY2UiOiJVQzFVTU8yNGdYSUJiM3hua01WZyIsImNsaWVudF9pZCI6ImVSZXplcHRBcHAiLCJzY29wZSI6Im9wZW5pZCBlLXJlemVwdCIsInN0YXRlIjoiaVVGRk9qRmJQWTlUVGdiZWlKSWMiLCJyZWRpcmVjdF91cmkiOiJodHRwOi8vcmVkaXJlY3QuZ2VtYXRpay5kZS9lcmV6ZXB0IiwiZXhwIjoxNjE1NTM4OTQyLCJpYXQiOjE2MTU1Mzg3NjIsImNvZGVfY2hhbGxlbmdlIjoiZE5YZmtqY3NOQ3UyeFg1MGIwcS1BUTI5VWF6VUt0RnhKa3ZtbmlQZFk2YyIsImp0aSI6ImRhZDg2ZjQ4NjkxN2YwODkifQ.TcTj1pJIWtO9Lk3SKHOjl-JVTzpBFGHbFd5LBV3icUc68mSUIf32EfNRkDjhyXHPpvwOLKrVTeQz5BncSI5Lyg"
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
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1615538942'>",
  "typ": "JWT",
  "kid": "idpSig"
}
{
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'qEwZXkUkzvLWlQQmKhhq1f4qdaoDqDmagTYLw-k7SME='>",
  "code_challenge_method": "S256",
  "token_type": "challenge",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'UC1UMO24gXIBb3xnkMVg'>",
  "client_id": "eRezeptApp",
  "scope": "openid e-rezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'iUFFOjFbPY9TTgbeiJIc'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1615538942'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1615538762'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: dNXfkjcsNCu2xX50b0q-AQ29UazUKtFxJkvmniPdY6c>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: 'dad86f486917f089'>"
}
```


## Authentication Request 

```
https://<FQDN Server>/<AUTHORIZATION_ENDPOINT>
Multiparts:
signed_challenge=eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJjdHkiOiJKV1QiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiR1YwdmxZVnloMDhuZm1pREZKNFp5dEFXRTNqT3U2VEVlMGpJWFEyTlNTNCIsInkiOiJHRTlBN29fMTRQbUdUMzBZSEV0SGs1ek9DaDJ4UUZ5OFUyWmtFdzk5SlNFIiwiY3J2IjoiQlAtMjU2In19.Fdr-NTaHUfusycsEq7JiOCwX14wAugCFxZ8jwGiCuxuWycEvIi9prw.mwjJEUyYgy2Hm8bf.7VtMipwsAScX3ucdsdowdt4CtQJ5fZhhutuRXpACgLRDvj-hh7kFDHT-5dRQzSzmKA2dMCaYfpFuM9VE07dFSf4wNHMacQMMwIW2Vq2uWZsUPyiN7ABdGa60LcZBRPBq2bH2Cc4_lI2PYIF6BrJM3a5PlGKKMCsKSKQcGvG8C8Wcnh3Rv9odOV8kq56etuLyt7UeHVSIZbwE7fzisa0ltxr_XVMOjR1IDCNhM2CE6lJuAAnImEWL9WtvxPuEWsMjiD-wW8Rzww9kBWD1Fwx1ikPWXfSp83t4WRfJA2B0NMg0ttw-deZL5SZKT-W5uVlCRmmrdfT1TnoUSuV2n2Oxc0pT3bBWR2euTQMD_hUXnQ119zILZAq9jfkeBEuVLZ3oFxIGa-oXAiW-OjfHSCW6QKXEFNNhLvRpe0ppGrYWkzLkYvzCvJQoSv0HjJs2bPzU0DYZDoprAkvUGwPiZN-4cpfhc8jJRo4LkCpOCIjQTRd6UMlESJR63zJX7RxBP7nQdcjG7f5xbSMm3qZKq5rY1gJQnnE2kS58phTt9ZOz4jPwCb7qD0M8LPy7FtgcpSZpZ48z8Bo93c0OIzK15Yi-fixnW1T2UAZObcfRbEPXCDAh_juLI2x8FYu_r-fkk9EPnIysh4ESZGE68IFF2RcMiE3n7We24KrYhVSZhPTfzChhri7R54OyBz6V-R8D_Psuv8RNlpIRQrFR7Zou4T_oO53FdLSpB_qG59ky5CwdsAx_2QKhFXYV2d558QXw8IIlDI75-9wtcGHnFKNNLGTQSb0YvmOYbyoJB_fiN3fkLNJzB6PSQCR3gUtKEkonbjaPLvuYVCWNmMRp_3Rg9UQB1wys_zKjVBsx2zKSiCmj93Jd4LS-vDQnB9rfs1EOSPjICuVo2oPbtKAu-7j0fkqNZAdpjcluw-JMTToDpxERE2gwljxo4Aahr_nV748MyP-ii-0AKvFXQOkPJNkCM2D7n_pmLc9G_Ha5nhCj_9NrRFxg3STLfaBsI6WAQega5fAzn1pu3Cv9gj1TB97GqK-M4xPFLhrc3LARC9sKzw6KT1zax8gEGqcLAMk1fSQa27Qa-IpH4uSjECNZVZgNIRKpAHY5711QZaYYEyR7qyzVbEJKOXGDJT_ykEXI39wYV-GGPoQPDvXNmupv4h8eKsfg2c2lndjJynKUOROfyvNnpm99aj4guh5FOfHr5GC8vhv840ZXj1fjPnSdmF5zmDUzexmnCGCGheTzJQ1kCNFqXuMMh3DTASWeVODRzBq8G-k1nLKlo9-6AbTvus3b_W1JkKHBvAZ5lPGICAQIMsV0N2CLCGQ-2BzCzV_HLXI17TjJBY8Oj0hEUePXeKJ7EF4X_Qx8fvudzIBwnssZ2Jr5yWxWSHS54t821jMH9m5GNhftxGtgKE7PkokVUBWHGiu3P4ziCpJOo1MNI2SNDf_Eu-DRpiH0cv-opxjXWwxvUhdb7h6IDjh0IEN9rtmbFENEQesWaxefwEy1rO3C4pbwDRToyLvQ1lIBZeUGybsQF-FXd4DuLZfACWNwejlBZgvC_8zQTmSKDn3Jc9wKyxdmiURJQNIg4WuJYtk60EwEPSE_HVh807DoDdxkxw6JVF72_VcINnZJ8tDFC3E8XngEr22CODWPtHX4uSY2fFS7AXG2iTP-KPcs7i1_U913e-2m9JPI4QsKQ_TGRyN8YgFMf2Tw827S3s5ZmQ9PuOHmnkALJfRLYZJ6wikDfdA4AwU2k-HgFMwo6vhvDQqcfzPGudM2DHqGGNkQcTQTloYp4TAijYi8xw2NNrDE-GAFXWWlDd2WPE9KXMtV9mf9BeI4cUW2-EWA5aHhiFYq2rfDh_QHec8QPJSYcy9cJPd6fgQi6TA3fZp3uvATDzmfw3kE5NmgJGFv0sGpylsiVp9SpwbR7C1YadNBzrPxI-UVFIje-EPyRgyNCo6g3zrD1SdT0Jw2oVmtgYRebX4ju4vqS3iZ74NlhXwW8JVH_eYigSSTsTf5nBBG7uoK7tPowSBMDcTCsdokkOFffEczFwRpukpHpKYQmy-qlvdsZQ2IVq5Dc4VWLo7yZMsvD7ZHAtpieF0exAyPpUJ4XglM9YIBRjZN03SVWX8-7LLX6pHAzwugDZhMfULgjrV5wRsGRiAztxdeQ48epWmfyOVNtRgebHeoHphpNzojF5ijg3tzfOUsvZgPtiGaa9hZs4WSNfCX_U2F1RnYhTxsoKKvcrBTeWK0f6EpDG2aESZaLAzLSw-m1WR5ZKNeXJD03sZcH5yrFmXtO11vWioc3BsAo3jvgi0IOt_ikLatdyYLI1jtESDvSErRcmVRl6WrbfsrS-NFx4J05tu32XtoL8_CDrNc3X-HmMI_Kp8r6bao6JyQbq72xaKhjjd_HLFA08PU5OOMKH659POoi-bVPwV_kuaT6eXFYZJIleI-Obro40Uz0KJ9HBxbNftZs1UxiQ9IhZlFY6G_A4SG58Nx-n_9Cte_-g4Sqbb7PX0lii6w19feBe-JC7bMsWk8i96gZBhwWf1gG1CINROurweGJPGnsL-C2ZO9F-XKLjV6srQstyDI_cbrYxVh5u4Nc1ISGW2PY7TSSawK7iuMtDyr1bwZU-lDJF2vJZXmEjFTE_3mpTfWUTej1e_9p9HnTESItKgM4Bav6xU2czxkpJthNs-GRXMmOycmbqI8bc5_0Sje6a2ActtQTC_uBeBrTgyQwNfVMCgqLEbHdjKypfMWknUCXpALETlTCGUg5RA7_EHMRLuX1Iv5RCFszCScmfuncp-vJP_3l9Nrh1eW2n_qu7TOmW5HUSDAvfmpqwMZ3LwvcJuFxYqdAOqavOx1uOC-_4OdXApMEKWqzjtI_XCqj_itXMgAzWR0IrBU_bVnijERXFJsecF6IFCCEPPuaN9uyUuOE5QYJkFju1FWW5RfWACXtb3nNpatkoLgJr8JWtsJyDncwgoCbAMfCnwzUvI8hbdefOMm7syCSGYaAwtCZ4DDy2c1xPSiXTtssdxCc4TGCx1kJxPzr0AiERmvx2GEA8zRhFQ8zQrH0_yWSsm2P6YllC7jWA3M2X2VTATCLoaB3wZhKCL_0OzH3QrAnkt2XruW-9Gh9nfuMnN3lnc6Eq6UjiuZUwLy0hK0VgcTdzwW5cq0Kd9BLwdgUDlBT060kN_dX8tTcnzyBsiGPOgiIOc_D-W2DKMlFYOZW1xYcyLpqBs5sijWVZK5YoEv9T1M7j55SbzZoqeGNSZ2jbfpL7uPWoXqY1Fht3LtRWrr4oLIB_a1FQ3amf5m8e3vulaar6We70oUwSVAq6ssucUczhBUBzkJtksBwJr3nEhBmBFdJl0665L80RIaO4VV4MDTVPgh0aA4pjbD6IDTEhdmGDb8Ucph_QtlT9cWmeQir_HsSpCH5-4sw3_c9p6GScWyF5imCcmGa4nml-4gaDFZeEzqE2T0lV8hzpWv2Rkr8PGF0v1h4fqKxrKNoA.9jicRQif7N-5Rfedor2txw

```

### Challenge Response (Encryption Header):

```
{
  "alg": "ECDH-ES+A256KW",
  "enc": "A256GCM",
  "cty": "JWT",
  "epk": {
    "kty": "EC",
    "x": "GV0vlYVyh08nfmiDFJ4ZytAWE3jOu6TEe0jIXQ2NSS4",
    "y": "GE9A7o_14PmGT30YHEtHk5zOCh2xQFy8U2ZkEw99JSE",
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
    ?code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE1NTM4ODIyLCJjdHkiOiJKV1QifQ..DpmLSfIFY6C7C4MP.SPeeskyyUeSWcuD6GtORu-37bK_lP6MzENomkZVi8FWQo6YpIIc0mbQaQJGtlCOr-3YkgaNTY66LU7MW_9EVuwuDyZfh6Gz931n8hZhjH00QGCy-hG2En2LCuDRCv7tDimDc4HtONFGNLn44rd2FWR2k942SgMS13lMmGI0mj5C21f0Ucp2_7ZSlfVbyYM6GLb1cDN1ArRFtlGN7PzNC4iVV7MVu9aQPhJd1yDyIvU3yOoTObZwr3hQxuCuWbJa4QwVlFl0iksJqkQ8Sk-_p9BGQUEuHm1z0lmxl9Lv7GvSQ-SKzijLZ8nLsIOE8M9FZmMSHAcdjxTjsiZC2CjZETxgqj5odmQ7S7UzN-ccUUS9mBcb5y-H66jjAt4AqlNkH-ANtLlRMCPpeGEPQx9G2Ke0LwuYrBVo1wVqKSQA61Bvo0yR1EV0ebXVayANksPU3IRzt77ptpniK0u_qHrUXxFkKQSnKKN3MF1s0jyxt0lfWxqlM7z0WUNhdDpxCB1Y7We4upROPGOyREUXqobdmeD-LIjQZ8Hbu6OgOyt4dK6jFhp1z31MGxifGbamKVrEpvItZBROokwDLALjgvEzS2XiuM7oB6FNKvkN8H7WXlFvrMfH6oRwdQTBeUInJ-Ixea2TXeNTb9U0z__MIhxSKY_5nglY3AiG8Y1vHIwF9FVT4m2qpsbzCbLb-ZchwXOSE9lHEKyR5TkqwhYi7ln9SQzsH3pIWrpV8ImLHw66O3CsyK_kB5wPMGe0kiAnKb8S56_kEQWRnC9rPMoQSskqWZNHxO5cgXGOGoiRSLbLtTSvf9A3gRfp4-2soAIsh4ogXtavIOMw2bapp9N4CnCe2wg-FFvZQaim1a2GF_IuYlTqi9j8kQZWI_In-Kb_Bd3gpyZr9TRZIUorjzb_qrefddnSgJSNLk6xRfGGPG5BNtZP0a5GuX39tsPglrgGjMXs-UZ9nn7A_vbWL6NOPotqN3oCzEDrNRV9OzMEIoeo8zAET4fDGXfh5n885Js6TEfN9BzT32xqQBRD21JKM74sByrBv6Z7HicpRUc-yCQ0qGbKzBoIcIYU-WVf3mOwQeZ76jcr_0kQE7hbmNRwCiTWgifXVWPFVQNUG-bX_yH05mI_qfUkY7fsdn1_pQtmUDTPqcrwfZqcmYTa3Lnd1SZ2urSt9dPRVLLeBKvemV3l3-MKarffiikrIETE6YwZbPOxQc-d601SV9g5eCtTk2KRykDwfitfpvrz1yQX4U99T99T1S2qe21esnFfDno-74z6qvvCFBssKyfpwsERoyJIPR35791ZjWWRYGMX6EH_f.JxAfZkcVovxgA27zu1eIgA
    &ssotoken=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE1NTgxOTYyLCJjdHkiOiJKV1QifQ..9aIjDzLJiESujHjs.P2I9vqPoDsJS2t_RMDVj85y1nBQmQ76z0JtDiJjl07WHF7fJAgGfNZ0onIZ0cJPSwf69LSEh3afBcaGe9kDJUIKg0EAALAK2OY0tnMyB4c5ZP7wLdr1Jik60_v10nyhQCr1j-xYdlzlYewZy0KwAcHLeH-Ulg2iMF0IXwSL_GB0PNU5KPN3fUlX4dzILdTgkB70Rl-z1LPSfUm1y9Sj3YcjpZWE6u9lUv9PRhfPK-gviAzauuGyu7e466UFHcP6xD7fQCFv6gyMV2m2uRKbauPBcYRiAp7PVG1ncZTjPpkQDNIHTeu16_gpNCbPF6xY1gy5LuhPEjAP5xMHKJ9XcKe4aAPcCfH7gB7uX0xRYCFl2BrSmj7kh_ZraLArJFfqgNcXpAXRa3lfsuuWsfsED5BtzI7nYncG9VyPSog9-3NLi7wSErlyR-8aVAUarj2R-AZpadcyayeiqJ6ojzNgQHvH_gXnblINm4ho6jSXTKVMkFYpE34iEFjfpxox3mIiJjp7FsdYSLTU0VIR3hI0m_bovXZYuqd2qmQALW24mNcmzPynjHYk-jEjk7m5KRjiS9el1luOLRKeZv5lVt-3xonf-sKOV2ggQX0t6GjgXlVVmnZXzjbgY-P51KL5ls7iUQV8SqsGyL2SA8M_lIPsR6ykYdcsU2t9MTZ5dYhVHsteq-mRIJ0cvWhU3dHNQmieOAC6IIgxCVrfQ7En-WP6lV9qc4CBER27VMTffO-R82-K02Yy5sFUdM8DVwxblOaFT5KGcH3XlUSOmINl65HGrm2ad5HacdLk6b0jSxxU--9CTFIUSZn2AAU7dTlLbOh6j7QHdcsytZDguzGNEa8IGtXyKKqMYlFvU245gdbBmvLsxRkDXgOmnvIQ4ab7j6mUV1GOQRRlSz4IkbQeQO1s9kIYK5vUTewIkla76ltB5pRrNvdYdg8pZMQMTsj4BibGMzAOjJN3eVq53WSjwubHtijaybOwZ5y_Nzq7qT2glLKDEpXul4jjUVWp_qkYB276u_EwlUN1f5Zb38TialA2orsDQREWnFVMahq9h1nFjwWg6PIko2uZQR4ashuhs_YWbe4sWn2b8ULj3rUWhyUD7n5pTUbAIrPWaUD6NcvpFMpRh9yZ8Aort769nPJfqnUxMba00SCcO_7Eh4muJS5yeHeeJjSq30473dIiUknl9IWYR8zI6lHznC7_6QRNZt4nHHrXYTh3JhfYIG63JvD2oLaHkN23fD6Y5CTgXnUUP8PPglKUflidZBHXnClOyT0BJUCPMb9LVOyuIEsoGNPWQWacPzvVQsOM1yYEtr9AvY7VyXjc6MzUvLmy9ChCSJisFmuFgKA3tQvpQmPsRvDDBwrza9wfU0plP46QBKxAwrUiOH0nvD3LehFZlgIQtidVtA8fBKgp5B4UWVg1fj9y6wAGFift27BOV8SNsORF66VrKlmkwPoeWfO-CNBQsvVGm2N6lhbg1e2gl6LAv69QHgp1AJ1_L56B0f4CjDaGG2tr9mXQnutA-uuRleuHmynSGcaN4U2XUQCcrnGhHbrVhYdc4PmDKW1TG64m0MRlV4QTFoF13bpof1LD_ddIMtVXVecvQiLzY1aYcb20l-gwsJw6ojAkObOgQyMKvFACw6ISABKizDozoJS7iZu-cvRgbVm0-27srIWn3Pg0QxtIBroSGcW8KGy8BWz0_wJYZthhaftTVty7sH_gX43XhX9jJ3qzs5oDpdUeTbTleqWACMoziexJm-qNIN11TeN2PHvpqbvRg9rn47MSR7mRtAsCfQ9SUK8dFVNR4zpYjYcDV8vwh3qtAuZSxnjHp_yKxva1LSIBHTzYe8IQxtz_E3_VfL9pwlYB6uIRDitXVZOoEqdb9uyTp2BjGHvF-GMAaaXw6UuPzC7vGwWhkP1tdck1QltJaBgwl82uRGz6NquDl6OtVftzrszSKSWuXu-pHBQXWrEvrZRoTFmmjVVGCpV5hPIw0o3zNOMU-VlNJeDOn_xniI_ZMovZ8Yo1944zlIy_PUpeprk2yQ3bL-wVL0fBF9m9K1SpLSndnIUyAWv7WcwgH_AmVeH2QuZRrXYO2PApoydUsPvlrqM0BU8jVumHOI55EE6BHEnAGy6GTPEJeFgEkw45YOt-9lxS_PGHNu5RKx5IIIJoZFI--Bs8eAmiFrfgRE8ud3kMH-UtWYzCYQRpNhuRH34v0Yohk95JSmNHx-L6GDdnr0hETT5wiHjmNJ_qlLE_AsdmtTwHVkTa6CukGuFGhmdzT7W_Eg5dfBZtU-1IcIZYhM3s_hl6LknT-pScIBijad31bt4mt8wGkjh81k_SsudwQ5ByZskfr9dRZJNWxasxgesxRPynYzCyy3bsuYr0JUC_v3Xg6WhfdaZu7AVo_13LvU9j6ee5Ip4kvuq2lbOscAKjoAVKJ0r5kcP2HXFg5hBESKf-Tm_Qkp3FZtOqAaSUWg3rn4uI9w0xLfkxtIVjbwIpyP4Hu1MQZCvHyI40Tf7YojDFt3Dktq29ShuB973HBma0WNVhIcbIoJurmgnHD_S8dcAkLZBwMJpmvnoK6SaXfcyoZeHxGEvAWtIpa_EqF6O4mttja92l6IiL40WqSN4cUHaj69SFk6C7Oz-A0lenZa7Tl4L41hpoE8CvHKccEQelhIisUriLEZ0ydF5LV6y7xIKVTg2RlHKS13JIks2Ohzt6uQKgX8rtYRObRGnSvsWyVUPCnSKfNr8x4cvIHCdGwffsVVhukvAwHbDJVqDWdqPz7eGzEmrqome2gRSDiuOc9DL5V5Xjpe_W662s-S_lYeCfD.8uX0ipuOEAYPokd1UqYIrw
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'iUFFOjFbPY9TTgbeiJIc'>,
Content-Length=0,
Date=<Zeitpunkt der Antwort. Beispiel 'Fri, 12 Mar 2021 08:46:02 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


### Authorization Code (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 1 Minuten. Beispiel: '1615538822'>",
  "cty": "JWT"
}
```


### Authorization Code (Decrypted):

```
{
  "alg": "BP256R1",
  "exp": "<Gültigkeit des Tokens von 1 Minuten. Beispiel: '1615538822'>",
  "typ": "JWT",
  "kid": "idpSig"
}
{
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'TGnBLEtEmM3mcWUBugha'>",
  "code_challenge_method": "S256",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "token_type": "code",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'UC1UMO24gXIBb3xnkMVg'>",
  "client_id": "eRezeptApp",
  "scope": "openid e-rezept",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1615538762'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'iUFFOjFbPY9TTgbeiJIc'>",
  "exp": "<Gültigkeit des Tokens von 1 Minuten. Beispiel: '1615538822'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1615538762'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: dNXfkjcsNCu2xX50b0q-AQ29UazUKtFxJkvmniPdY6c>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '85c599c97cbf1015'>"
}
```


### SSO Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1615581962'>",
  "cty": "JWT"
}
```


### SSO Token (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1615581962'>",
  "kid": "idpSig"
}
{
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1615538762'>",
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
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1615581962'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1615538762'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>"
}
```


## Token Request 

```
https://<FQDN Server>/<TOKEN_ENDPOINT>
Multiparts:
client_id=eRezeptApp
code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE1NTM4ODIyLCJjdHkiOiJKV1QifQ..DpmLSfIFY6C7C4MP.SPeeskyyUeSWcuD6GtORu-37bK_lP6MzENomkZVi8FWQo6YpIIc0mbQaQJGtlCOr-3YkgaNTY66LU7MW_9EVuwuDyZfh6Gz931n8hZhjH00QGCy-hG2En2LCuDRCv7tDimDc4HtONFGNLn44rd2FWR2k942SgMS13lMmGI0mj5C21f0Ucp2_7ZSlfVbyYM6GLb1cDN1ArRFtlGN7PzNC4iVV7MVu9aQPhJd1yDyIvU3yOoTObZwr3hQxuCuWbJa4QwVlFl0iksJqkQ8Sk-_p9BGQUEuHm1z0lmxl9Lv7GvSQ-SKzijLZ8nLsIOE8M9FZmMSHAcdjxTjsiZC2CjZETxgqj5odmQ7S7UzN-ccUUS9mBcb5y-H66jjAt4AqlNkH-ANtLlRMCPpeGEPQx9G2Ke0LwuYrBVo1wVqKSQA61Bvo0yR1EV0ebXVayANksPU3IRzt77ptpniK0u_qHrUXxFkKQSnKKN3MF1s0jyxt0lfWxqlM7z0WUNhdDpxCB1Y7We4upROPGOyREUXqobdmeD-LIjQZ8Hbu6OgOyt4dK6jFhp1z31MGxifGbamKVrEpvItZBROokwDLALjgvEzS2XiuM7oB6FNKvkN8H7WXlFvrMfH6oRwdQTBeUInJ-Ixea2TXeNTb9U0z__MIhxSKY_5nglY3AiG8Y1vHIwF9FVT4m2qpsbzCbLb-ZchwXOSE9lHEKyR5TkqwhYi7ln9SQzsH3pIWrpV8ImLHw66O3CsyK_kB5wPMGe0kiAnKb8S56_kEQWRnC9rPMoQSskqWZNHxO5cgXGOGoiRSLbLtTSvf9A3gRfp4-2soAIsh4ogXtavIOMw2bapp9N4CnCe2wg-FFvZQaim1a2GF_IuYlTqi9j8kQZWI_In-Kb_Bd3gpyZr9TRZIUorjzb_qrefddnSgJSNLk6xRfGGPG5BNtZP0a5GuX39tsPglrgGjMXs-UZ9nn7A_vbWL6NOPotqN3oCzEDrNRV9OzMEIoeo8zAET4fDGXfh5n885Js6TEfN9BzT32xqQBRD21JKM74sByrBv6Z7HicpRUc-yCQ0qGbKzBoIcIYU-WVf3mOwQeZ76jcr_0kQE7hbmNRwCiTWgifXVWPFVQNUG-bX_yH05mI_qfUkY7fsdn1_pQtmUDTPqcrwfZqcmYTa3Lnd1SZ2urSt9dPRVLLeBKvemV3l3-MKarffiikrIETE6YwZbPOxQc-d601SV9g5eCtTk2KRykDwfitfpvrz1yQX4U99T99T1S2qe21esnFfDno-74z6qvvCFBssKyfpwsERoyJIPR35791ZjWWRYGMX6EH_f.JxAfZkcVovxgA27zu1eIgA
grant_type=authorization_code
key_verifier=eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJjdHkiOiJKU09OIiwiZXBrIjp7Imt0eSI6IkVDIiwieCI6Im5KOF9KQzlUWmp4VmhrSmFQb0ZIemx2b2lhNmtMS3o3QkxVNjJYenJUMVUiLCJ5IjoiZklmV3p5d20wdkI5YjlvMUN5Zk1Ncnp4TE1KdVVvdUVmY19ERlRUbGM4USIsImNydiI6IkJQLTI1NiJ9fQ.kwz9IhRQCGj5qkRq4K_Qmv_PDP9WkW127KHbHcV1uUp-nMK1a_5xjg.4eiKwQgSqDMSx4Vo.2oQB1oLcvg8PvC2pnJMX4MjKE8fPtutg91DyPAzofmKEarYiBknSVOUsqRnWxN7OGyfeQMg5x5tHh-igIE6srnIMHdeuS-bLGNLrZ29q_iaWCxh0aHIHx6IB6IfZRA42WNlN7RoOvRwhoAW2oRpLiZZ29TDLIW1SVoc.-rC-8WHgp4snGES6qyX14g
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
    "x": "nJ8_JC9TZjxVhkJaPoFHzlvoia6kLKz7BLU62XzrT1U",
    "y": "fIfWzywm0vB9b9o1CyfMMrzxLMJuUouEfc_DFTTlc8Q",
    "crv": "BP-256"
  }
}
```


Key verifier (Body)


```
{
  "token_key": "dHZLTmxNT0x6NnFka2hSVXRNR0JUa3RRakxPbjZsVVA=",
  "code_verifier": "02-xrbFUnXgpUlQzzijwcNrkjsNEfok1Vvdu1G3aqqs"
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
Date=<Zeitpunkt der Antwort. Beispiel 'Fri, 12 Mar 2021 08:46:02 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "expires_in": 300,
  "token_type": "Bearer",
  "id_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE1NTM5MDYyLCJjdHkiOiJKV1QifQ..il-DXmhcCN1W2PIe.luz-g8NAqnMtRheO27PyalO7MzsCqvs2Fis-5ehdkscOJBuraJMkW1qnCIYhyZyeKSOLIbRE_IDLabAeXkhTjajAFuVL4xPeVkJJ_KODiIb4jfvbg4gWqLHm-qH7DnZHglW_8Mf7vQIt0oVTQX_QaSxIuPaGSxVlVrvxIxEq-Ti2RxCHmCs6Tbp4E4bVMgyL95rpazuYtiA6dE0XM7B9005tULb-gqnulYCuGoE7nzRCuMKeXpDMDbJDhJix_CxvDOw0d4LPpHNrpJVxXUcHtZC6w2csWu4ywiC3OiZ0G2HQ0HSKw6nytaCGH3QoeWr5jl6xeOylDRZQmxzT2v1ANyDSHpgL_NYmoqdXtcVCp8jslDa_PUvUE4o4qvasTd8aRwHRQdHOak7QskSMA-gEFXUp1BrSilHsRzDCofOZ6Bgv18iMJdbyvHowd75mVC21g6eB_x4KSD8QFC-nF6qTLEotioJ60OoDyimDE_ENzSmV0dWUCmww74v8VJ7X-h-9gwFTvQu_yf2jpf7LAhIN4cm0RZKV5d53NNat7dSvM6drDLWAre89lJGNcby7EMcWfMrmXdjQkVa2OjGRGvvnAt85RVdvDvX4ilS1_5YbY48pFUvAuSK1hL8BIJmm3sapdwaLr4VH7zf79Gqm0_7bP1pWcX9SZl28Bjibf5RnCxnxn4quq3rZpxnUFDkkOkX0IF2e814GqF-bpBW1zpUouXswL4Px2lhlAXoKmUeBA04FXrsNoA86pjP-IxQJa9Kg6CUFTzwOIYnJYhBRLew57_-nzkvnfqrw_GjFVCYnKBRLxbhVImC_xSNtEGoeZBjB35_dftP6xvSZ9qQkGrqrO5Cm431NB24fxtTFo1Biq2X5jaKIo0aSWGYnmUSjPePn1i7hrG-SRI_arFD3PGF03u953yv0BWvnfmD9t5yzREPWq6ZD7TpfIQ8l63H_zF0Hzk9VtdtcaEwRlW4p7tJ9fdaYBIUgO4AD5NmhqvDOSs81nJQJm-dlkuQE-KOmweIkijCaXSNy-2GXKs3VTE26gN7eMeuh6-PA5QpiDWsVtHHIKUmliDmqHG-VRjyo6NrO844O0gQCZ9H0.sg5kVnXxLBeM4dIgfw-4PQ",
  "access_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE1NTM5MDYyLCJjdHkiOiJKV1QifQ..8U7oeg5DQSjaELC4.mib_5OtjAnywTVzAAIWGnLx4h8IIXu90-yGBd3UX2BYYtHvUYLv51fRDmXUL7vmeZUvC2WWZBo4WmyYVfp8j_qXh7Q1t4nT0Q9Y3X871wTi4VRXPLOdGn8z-vL7g9AXAj2cNl5hmEXJz6bpg_W4ngzToChj8ZjVU4hBcq74ic8xxaAo9yLxSe3HJVZpljFF-fokS7VbTcuYm5GI10-faSLKzMP2B9zjPC4QHAhhQT2ptC1NyECYrmT6ZdI58ZfPr9kaDSQdnOVKXUh3MqqCg0-KkfT3VayDle-puZxxmDWhVscpYuQn1UVbIi0mQexau4h5lbPD_kFBEkjIJTJE8MoJoC_GRirw0Sc1I0PDZufLnuOuesaCviybdSiS6YlNqxsLVh7X26ArYT-5srVFz-UMVwB1bsoDFsS-y5AjRWshkIfnl-sKCk_lqP9mSvDNs5EY4C-8UevC3fQzg7hiceGNUSzT9H6iys3tT6A7fJvzDoifguxLpMJAAPlPKWEY4BX-k_QdmgG5ktI3rRNxSwRCcEXntg7oWNxDoxjM5_Qj0CkVl03caw1fpvSgqPYmESoZgZ4Orqj1kOGS8Ef7FVGXHXJ3JKME52EkXlKSQggYFbS-G3cU-G0if8Lp-iQg4xQPYnst4VOG4Za-wGDakVPEwxJXmRgOw3riwLshEeYjLHDhyLj4ZC-rbfHF2u12RMlG53QabV4e-G4WH1cDk6pqMFi2v6Eoah5hsmofyEVfmNM6flC6nGjB9K21231S-vulT4BEyl_SwLGxg3rfmlJkSiQrbDw81gBHc3I82ZYfFumPku3HG002BY4sppeGCJqRsBdjmUdXwzrMd2GZXF5dsbjOSj7tfn4nEMU05lNLanrzSRomRvAthxVLf6zoek2BLid2hR1DVLqyPJfyl9xZsYFFe4769so19Yt91mNgTMMe1S1ctLSEjP0kLRCFWMTasiH33WgdTVTuxyBb5CxdxfyQmc6s7qmDpRYyEVKiF723WgeBkrOOYT0E4nyPjf2H2ycs1dXsSNQAbrDxcj62npfCLNQeww3JLeH4gAwtkszdT6E1DurGTNR1QUGHzZfyNE5zLzUVI_gnHvXpc0bKYPQ.O6EbTWwr-sBleyyLARK8hw"
}
```


### Access Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1615539062'>",
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
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1615538762'>",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1615539062'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1615538762'>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '4113d93cb630e15e'>"
}
```


### ID Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1615539062'>",
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
  "at_hash": "<Erste 16 Bytes des Hash des Authentication Tokens Base64(subarray(Sha256(authentication_token), 0, 16)). Beispiel: '0DsHXlS01s2h3U7l4QXU2A'>",
  "sub": "<subject. Base64(sha256(audClaim + idNummerClaim + serverSubjectSalt)). Beispiel: 'qDAmiQOl5_rJ5-ok48lbjSs6QH9oya7VuxUJ-_E1HCw'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "amr": "["mfa", "sc", "pin"]",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'UC1UMO24gXIBb3xnkMVg'>",
  "aud": "eRezeptApp",
  "acr": "gematik-ehealth-loa-high",
  "azp": "eRezeptApp",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1615538762'>",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1615539062'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1615538762'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: 'c192fa4f9287ac20'>"
}
```


# SSO Flow 
## Authorization Request 

```
https://<FQDN Server>/<AUTHORIZATION_ENDPOINT>
    ?client_id=eRezeptApp
    &response_type=code
    &redirect_uri=http://redirect.gematik.de/erezept
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'dwbqOo0w36u9lBoWp7kc'>
    &code_challenge=<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: OYJanKF2_u6xOf55Wff4pXe3XAuCG0A6wZoiB59nRLI>
    &code_challenge_method=S256
    &scope=openid+e-rezept
    &nonce=<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'jnTKmBdGCITCOfMy4Vgh'>

```

## Authorization Response 

```
200
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Transfer-Encoding=chunked,
Date=<Zeitpunkt der Antwort. Beispiel 'Fri, 12 Mar 2021 08:46:02 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "challenge": {
    "rawString": "eyJhbGciOiJCUDI1NlIxIiwiZXhwIjoxNjE1NTM4OTQyLCJ0eXAiOiJKV1QiLCJraWQiOiJpZHBTaWcifQ.eyJpc3MiOiJodHRwczovL2lkcC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJzbmMiOiJheW9ZakhwRVFDM2FMdkpraGpJLXd5Z0l1dTVCYy1tVUU4MXRudF90eHdvPSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJ0b2tlbl90eXBlIjoiY2hhbGxlbmdlIiwibm9uY2UiOiJqblRLbUJkR0NJVENPZk15NFZnaCIsImNsaWVudF9pZCI6ImVSZXplcHRBcHAiLCJzY29wZSI6Im9wZW5pZCBlLXJlemVwdCIsInN0YXRlIjoiZHdicU9vMHczNnU5bEJvV3A3a2MiLCJyZWRpcmVjdF91cmkiOiJodHRwOi8vcmVkaXJlY3QuZ2VtYXRpay5kZS9lcmV6ZXB0IiwiZXhwIjoxNjE1NTM4OTQyLCJpYXQiOjE2MTU1Mzg3NjIsImNvZGVfY2hhbGxlbmdlIjoiT1lKYW5LRjJfdTZ4T2Y1NVdmZjRwWGUzWEF1Q0cwQTZ3Wm9pQjU5blJMSSIsImp0aSI6IjE4MWJhNmI2NzljZDQ1YzgifQ.phfZIYlgXRX5FXUZLep1tsZ2SzBcrCPKVVYTQFAt-gYJ3tYZfrWvHWOD8T9uBoJGOXMKAbckY82hw54od88zfQ"
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
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1615538942'>",
  "typ": "JWT",
  "kid": "idpSig"
}
{
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'ayoYjHpEQC3aLvJkhjI-wygIuu5Bc-mUE81tnt_txwo='>",
  "code_challenge_method": "S256",
  "token_type": "challenge",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'jnTKmBdGCITCOfMy4Vgh'>",
  "client_id": "eRezeptApp",
  "scope": "openid e-rezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'dwbqOo0w36u9lBoWp7kc'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1615538942'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1615538762'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: OYJanKF2_u6xOf55Wff4pXe3XAuCG0A6wZoiB59nRLI>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '181ba6b679cd45c8'>"
}
```


## Authentication Request 

```
https://<FQDN Server>/<SSO_ENDPOINT>
Multiparts:
ssotoken=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE1NTgxOTYyLCJjdHkiOiJKV1QifQ..9aIjDzLJiESujHjs.P2I9vqPoDsJS2t_RMDVj85y1nBQmQ76z0JtDiJjl07WHF7fJAgGfNZ0onIZ0cJPSwf69LSEh3afBcaGe9kDJUIKg0EAALAK2OY0tnMyB4c5ZP7wLdr1Jik60_v10nyhQCr1j-xYdlzlYewZy0KwAcHLeH-Ulg2iMF0IXwSL_GB0PNU5KPN3fUlX4dzILdTgkB70Rl-z1LPSfUm1y9Sj3YcjpZWE6u9lUv9PRhfPK-gviAzauuGyu7e466UFHcP6xD7fQCFv6gyMV2m2uRKbauPBcYRiAp7PVG1ncZTjPpkQDNIHTeu16_gpNCbPF6xY1gy5LuhPEjAP5xMHKJ9XcKe4aAPcCfH7gB7uX0xRYCFl2BrSmj7kh_ZraLArJFfqgNcXpAXRa3lfsuuWsfsED5BtzI7nYncG9VyPSog9-3NLi7wSErlyR-8aVAUarj2R-AZpadcyayeiqJ6ojzNgQHvH_gXnblINm4ho6jSXTKVMkFYpE34iEFjfpxox3mIiJjp7FsdYSLTU0VIR3hI0m_bovXZYuqd2qmQALW24mNcmzPynjHYk-jEjk7m5KRjiS9el1luOLRKeZv5lVt-3xonf-sKOV2ggQX0t6GjgXlVVmnZXzjbgY-P51KL5ls7iUQV8SqsGyL2SA8M_lIPsR6ykYdcsU2t9MTZ5dYhVHsteq-mRIJ0cvWhU3dHNQmieOAC6IIgxCVrfQ7En-WP6lV9qc4CBER27VMTffO-R82-K02Yy5sFUdM8DVwxblOaFT5KGcH3XlUSOmINl65HGrm2ad5HacdLk6b0jSxxU--9CTFIUSZn2AAU7dTlLbOh6j7QHdcsytZDguzGNEa8IGtXyKKqMYlFvU245gdbBmvLsxRkDXgOmnvIQ4ab7j6mUV1GOQRRlSz4IkbQeQO1s9kIYK5vUTewIkla76ltB5pRrNvdYdg8pZMQMTsj4BibGMzAOjJN3eVq53WSjwubHtijaybOwZ5y_Nzq7qT2glLKDEpXul4jjUVWp_qkYB276u_EwlUN1f5Zb38TialA2orsDQREWnFVMahq9h1nFjwWg6PIko2uZQR4ashuhs_YWbe4sWn2b8ULj3rUWhyUD7n5pTUbAIrPWaUD6NcvpFMpRh9yZ8Aort769nPJfqnUxMba00SCcO_7Eh4muJS5yeHeeJjSq30473dIiUknl9IWYR8zI6lHznC7_6QRNZt4nHHrXYTh3JhfYIG63JvD2oLaHkN23fD6Y5CTgXnUUP8PPglKUflidZBHXnClOyT0BJUCPMb9LVOyuIEsoGNPWQWacPzvVQsOM1yYEtr9AvY7VyXjc6MzUvLmy9ChCSJisFmuFgKA3tQvpQmPsRvDDBwrza9wfU0plP46QBKxAwrUiOH0nvD3LehFZlgIQtidVtA8fBKgp5B4UWVg1fj9y6wAGFift27BOV8SNsORF66VrKlmkwPoeWfO-CNBQsvVGm2N6lhbg1e2gl6LAv69QHgp1AJ1_L56B0f4CjDaGG2tr9mXQnutA-uuRleuHmynSGcaN4U2XUQCcrnGhHbrVhYdc4PmDKW1TG64m0MRlV4QTFoF13bpof1LD_ddIMtVXVecvQiLzY1aYcb20l-gwsJw6ojAkObOgQyMKvFACw6ISABKizDozoJS7iZu-cvRgbVm0-27srIWn3Pg0QxtIBroSGcW8KGy8BWz0_wJYZthhaftTVty7sH_gX43XhX9jJ3qzs5oDpdUeTbTleqWACMoziexJm-qNIN11TeN2PHvpqbvRg9rn47MSR7mRtAsCfQ9SUK8dFVNR4zpYjYcDV8vwh3qtAuZSxnjHp_yKxva1LSIBHTzYe8IQxtz_E3_VfL9pwlYB6uIRDitXVZOoEqdb9uyTp2BjGHvF-GMAaaXw6UuPzC7vGwWhkP1tdck1QltJaBgwl82uRGz6NquDl6OtVftzrszSKSWuXu-pHBQXWrEvrZRoTFmmjVVGCpV5hPIw0o3zNOMU-VlNJeDOn_xniI_ZMovZ8Yo1944zlIy_PUpeprk2yQ3bL-wVL0fBF9m9K1SpLSndnIUyAWv7WcwgH_AmVeH2QuZRrXYO2PApoydUsPvlrqM0BU8jVumHOI55EE6BHEnAGy6GTPEJeFgEkw45YOt-9lxS_PGHNu5RKx5IIIJoZFI--Bs8eAmiFrfgRE8ud3kMH-UtWYzCYQRpNhuRH34v0Yohk95JSmNHx-L6GDdnr0hETT5wiHjmNJ_qlLE_AsdmtTwHVkTa6CukGuFGhmdzT7W_Eg5dfBZtU-1IcIZYhM3s_hl6LknT-pScIBijad31bt4mt8wGkjh81k_SsudwQ5ByZskfr9dRZJNWxasxgesxRPynYzCyy3bsuYr0JUC_v3Xg6WhfdaZu7AVo_13LvU9j6ee5Ip4kvuq2lbOscAKjoAVKJ0r5kcP2HXFg5hBESKf-Tm_Qkp3FZtOqAaSUWg3rn4uI9w0xLfkxtIVjbwIpyP4Hu1MQZCvHyI40Tf7YojDFt3Dktq29ShuB973HBma0WNVhIcbIoJurmgnHD_S8dcAkLZBwMJpmvnoK6SaXfcyoZeHxGEvAWtIpa_EqF6O4mttja92l6IiL40WqSN4cUHaj69SFk6C7Oz-A0lenZa7Tl4L41hpoE8CvHKccEQelhIisUriLEZ0ydF5LV6y7xIKVTg2RlHKS13JIks2Ohzt6uQKgX8rtYRObRGnSvsWyVUPCnSKfNr8x4cvIHCdGwffsVVhukvAwHbDJVqDWdqPz7eGzEmrqome2gRSDiuOc9DL5V5Xjpe_W662s-S_lYeCfD.8uX0ipuOEAYPokd1UqYIrw
unsigned_challenge=eyJhbGciOiJCUDI1NlIxIiwiZXhwIjoxNjE1NTM4OTQyLCJ0eXAiOiJKV1QiLCJraWQiOiJpZHBTaWcifQ.eyJpc3MiOiJodHRwczovL2lkcC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJzbmMiOiJheW9ZakhwRVFDM2FMdkpraGpJLXd5Z0l1dTVCYy1tVUU4MXRudF90eHdvPSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJ0b2tlbl90eXBlIjoiY2hhbGxlbmdlIiwibm9uY2UiOiJqblRLbUJkR0NJVENPZk15NFZnaCIsImNsaWVudF9pZCI6ImVSZXplcHRBcHAiLCJzY29wZSI6Im9wZW5pZCBlLXJlemVwdCIsInN0YXRlIjoiZHdicU9vMHczNnU5bEJvV3A3a2MiLCJyZWRpcmVjdF91cmkiOiJodHRwOi8vcmVkaXJlY3QuZ2VtYXRpay5kZS9lcmV6ZXB0IiwiZXhwIjoxNjE1NTM4OTQyLCJpYXQiOjE2MTU1Mzg3NjIsImNvZGVfY2hhbGxlbmdlIjoiT1lKYW5LRjJfdTZ4T2Y1NVdmZjRwWGUzWEF1Q0cwQTZ3Wm9pQjU5blJMSSIsImp0aSI6IjE4MWJhNmI2NzljZDQ1YzgifQ.phfZIYlgXRX5FXUZLep1tsZ2SzBcrCPKVVYTQFAt-gYJ3tYZfrWvHWOD8T9uBoJGOXMKAbckY82hw54od88zfQ

```

### SSO Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1615581962'>",
  "cty": "JWT"
}
```


### SSO Token (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1615581962'>",
  "kid": "idpSig"
}
{
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1615538762'>",
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
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1615581962'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1615538762'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>"
}
```


### Unsigned Challenge:

```
{
  "alg": "BP256R1",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1615538942'>",
  "typ": "JWT",
  "kid": "idpSig"
}
{
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'ayoYjHpEQC3aLvJkhjI-wygIuu5Bc-mUE81tnt_txwo='>",
  "code_challenge_method": "S256",
  "token_type": "challenge",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'jnTKmBdGCITCOfMy4Vgh'>",
  "client_id": "eRezeptApp",
  "scope": "openid e-rezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'dwbqOo0w36u9lBoWp7kc'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1615538942'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1615538762'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: OYJanKF2_u6xOf55Wff4pXe3XAuCG0A6wZoiB59nRLI>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '181ba6b679cd45c8'>"
}
```


## Authentication Response 

```
302
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Location=https://<FQDN Server>//erezept/token
    ?code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE1NTQyMzYyLCJjdHkiOiJKV1QifQ..O-LL8rwy-Dpq6fGN.VG9HXeRVV3cHfmfe2sp8BGMlXA5h5rOWdPy6Vse-xSaT3OOveV-2ze-c_plYC_mggTGDkFhMLf5sso7jqGAj9-RCjpQdXI0dehc0Lhyow77aSulJoZ9WIDd_mF04aGI4xnPXpg5JjO4UeeZcmZXl0bIwLSGHuQzVQkQMY5Q1N6-CXDwYOWs_FHcWrMihq3gRp9zmCKjLlIBxbjnHrckDfml5BvNFclEiyHo91HgMRpj0m0b9MOmCAhDEnnQZ6-NKplrxgBb_yRHSJCLolmxEZZ7y0XbgqMql_mp3xZ-PjI6LEXY9m1Uoc-mVVIFmopIkvSop5O09ovxpvP7qYY6qywomWIDDjQMEjgGhwv5aVcQkS2X6iMrEdKnsaYm8rFZ3mlZMk8KKv1tcNQMDsS2l4mB0EDXKkWmdOPAr3xzelStlGojQobCZQTvR3Tg06YCz_nR90UZ3Kov6Ib-UH9_RMf3M2UeqKGRgmU7D-U29P1xdFJ9izZ6zB7YQvoSCzFbvxDbdoIhbAGcuqKSVvycMBdc5_AaTMhJca5zzvPLSB_0lPaUv9sEvVnfXuJ8M_OhtnTJXy11tWIFBCSuZgU8T8D5k6AglbDRKqcFT31Y404zwHfQ3f6etkGBCvBRFHJ_MPygDAG2G9lYeOd-oWHS7vYi7HK8D-454kw3HZe7BS1Y4-3Qv9JG51X5g_8UlC1do-H0FgngL1KPl1Nyaui3gZ6LRM1JZ0Im6aRXg7p2tWmjHiwd6kFPNu9x0QhnSgA9_xafdbj1DiGXImjjQ30dY_YSk9eqDjj06aq-4oA4yQ9KisALqdxz_atSOSfxsap0eHA32tCY4s1MCKcIaDWF2uz_KTomOg7FL1SapUs9sqQNF9RCosx4xxBhCX5JBMFZcpPS6C0ARSVf9iDAnVYDMhLFEVr6d1cbsEXo7Ot2-ANe4a4OIRmmXYfRdvOieUQ5txNg-NBUYVl1BqAPIu6S53TKvDC9Vgqo6bH7USSPCZCr6c7cpa97tnM0QPpIz7khLDgTLN4O5IfzxKT3U1aMas8Mv1ZMN2J7hcN0a-HnxiejlrssSXKLbUyvZAvwh5XGGmiP75-yAYvQuXy-yuP_QXVibK_dvpvzKLD1gzEB5QcNAnKi9hTGZZIcxhvIpYhwOLgfwSg0oPj8A-19umhBaKx5x9gccwtuc-GOGFBaiSeoS8VHrfTkD_SCssLGmf-A3ggeQi9cCOfbuv_G2x831-ygoV27SFJ4e6WWnVnKhnTiZBwh8t44pBimebIbxOZ79MiJzq22JSME.-ijSOljacdZTr62YycLErA
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'dwbqOo0w36u9lBoWp7kc'>,
Content-Length=0,
Date=<Zeitpunkt der Antwort. Beispiel 'Fri, 12 Mar 2021 08:46:02 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


### Authorization Code (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 1 Stunden. Beispiel: '1615542362'>",
  "cty": "JWT"
}
```


### Authorization Code (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "exp": "<Gültigkeit des Tokens von 1 Stunden. Beispiel: '1615542362'>",
  "kid": "idpSig"
}
{
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'GkeCqEeod7wOkmMd8obr'>",
  "code_challenge_method": "S256",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "token_type": "code",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'jnTKmBdGCITCOfMy4Vgh'>",
  "client_id": "eRezeptApp",
  "scope": "openid e-rezept",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1615538762'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'dwbqOo0w36u9lBoWp7kc'>",
  "exp": "<Gültigkeit des Tokens von 1 Stunden. Beispiel: '1615542362'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: OYJanKF2_u6xOf55Wff4pXe3XAuCG0A6wZoiB59nRLI>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: 'ba0e4bdb8769d44e'>"
}
```


## Token Request 

```
https://<FQDN Server>/<TOKEN_ENDPOINT>
Multiparts:
client_id=eRezeptApp
code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE1NTQyMzYyLCJjdHkiOiJKV1QifQ..O-LL8rwy-Dpq6fGN.VG9HXeRVV3cHfmfe2sp8BGMlXA5h5rOWdPy6Vse-xSaT3OOveV-2ze-c_plYC_mggTGDkFhMLf5sso7jqGAj9-RCjpQdXI0dehc0Lhyow77aSulJoZ9WIDd_mF04aGI4xnPXpg5JjO4UeeZcmZXl0bIwLSGHuQzVQkQMY5Q1N6-CXDwYOWs_FHcWrMihq3gRp9zmCKjLlIBxbjnHrckDfml5BvNFclEiyHo91HgMRpj0m0b9MOmCAhDEnnQZ6-NKplrxgBb_yRHSJCLolmxEZZ7y0XbgqMql_mp3xZ-PjI6LEXY9m1Uoc-mVVIFmopIkvSop5O09ovxpvP7qYY6qywomWIDDjQMEjgGhwv5aVcQkS2X6iMrEdKnsaYm8rFZ3mlZMk8KKv1tcNQMDsS2l4mB0EDXKkWmdOPAr3xzelStlGojQobCZQTvR3Tg06YCz_nR90UZ3Kov6Ib-UH9_RMf3M2UeqKGRgmU7D-U29P1xdFJ9izZ6zB7YQvoSCzFbvxDbdoIhbAGcuqKSVvycMBdc5_AaTMhJca5zzvPLSB_0lPaUv9sEvVnfXuJ8M_OhtnTJXy11tWIFBCSuZgU8T8D5k6AglbDRKqcFT31Y404zwHfQ3f6etkGBCvBRFHJ_MPygDAG2G9lYeOd-oWHS7vYi7HK8D-454kw3HZe7BS1Y4-3Qv9JG51X5g_8UlC1do-H0FgngL1KPl1Nyaui3gZ6LRM1JZ0Im6aRXg7p2tWmjHiwd6kFPNu9x0QhnSgA9_xafdbj1DiGXImjjQ30dY_YSk9eqDjj06aq-4oA4yQ9KisALqdxz_atSOSfxsap0eHA32tCY4s1MCKcIaDWF2uz_KTomOg7FL1SapUs9sqQNF9RCosx4xxBhCX5JBMFZcpPS6C0ARSVf9iDAnVYDMhLFEVr6d1cbsEXo7Ot2-ANe4a4OIRmmXYfRdvOieUQ5txNg-NBUYVl1BqAPIu6S53TKvDC9Vgqo6bH7USSPCZCr6c7cpa97tnM0QPpIz7khLDgTLN4O5IfzxKT3U1aMas8Mv1ZMN2J7hcN0a-HnxiejlrssSXKLbUyvZAvwh5XGGmiP75-yAYvQuXy-yuP_QXVibK_dvpvzKLD1gzEB5QcNAnKi9hTGZZIcxhvIpYhwOLgfwSg0oPj8A-19umhBaKx5x9gccwtuc-GOGFBaiSeoS8VHrfTkD_SCssLGmf-A3ggeQi9cCOfbuv_G2x831-ygoV27SFJ4e6WWnVnKhnTiZBwh8t44pBimebIbxOZ79MiJzq22JSME.-ijSOljacdZTr62YycLErA
grant_type=authorization_code
key_verifier=eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJjdHkiOiJKU09OIiwiZXBrIjp7Imt0eSI6IkVDIiwieCI6IlFKdTBCcnQ0VU5yVEluQlIyaUtRdXpJOXZ4R1Y2RmNsbTBEd1l1bzdFRzgiLCJ5IjoiSDgtQzhMM0xhRFd2QW9UNUFBZjdiNWFQa05IQ0RRNms0dVY2c3A1LVBfWSIsImNydiI6IkJQLTI1NiJ9fQ.-tmapOQ7gMI7dke2H7MZ3yFcwioDrzfiv-i8j87KgcBv9dhgqQn3cg.8wD2WQRv5MxFe4y_.gf8vqME08OTRdyPVEZjo2w0mfzN7vTczBjNrcLgUZtDaIyXXi8o38pY-e4EsIHXgxImjNkKg0MXIS2w3kU6K0uiQEvmbhOMfeX0Rs8W-yyXr5w9Tdhadind66meeHbPZ3JnpkGtJEV3BuiLgxpN-e8QD4VZrgmA_kFE.ccGkytjdq9XuZY00ekBsSw
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
    "x": "QJu0Brt4UNrTInBR2iKQuzI9vxGV6Fclm0DwYuo7EG8",
    "y": "H8-C8L3LaDWvAoT5AAf7b5aPkNHCDQ6k4uV6sp5-P_Y",
    "crv": "BP-256"
  }
}
```


Key verifier (Body)


```
{
  "token_key": "MkwybmlESHREc3NWbEEzOTZQc2h3UHBVeTZjZ0g2SnA=",
  "code_verifier": "WlkzAu1X0KY3GLLBZogJfwYKqhkm4-CF8YJZxp-1M_Q"
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
Date=<Zeitpunkt der Antwort. Beispiel 'Fri, 12 Mar 2021 08:46:02 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "expires_in": 300,
  "token_type": "Bearer",
  "id_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE1NTM5MDYyLCJjdHkiOiJKV1QifQ.._3QQvc4StM7xNqsr.rvKcFFqCo44gSeC2jaKm4NgPtivU1gTCMWKzaiHIj6KmU4lfX7_q9jkf-gZ4KRi8xBdmJoTyL7sCV237HRQy9UqPzQRU7fxXYCC0lbx_J2ofkl29IZ02b1VMgvNP35oS3bRulGBtl60H0MYVSBgwTNqPTvOofQkVj7Bq7t97PYREUT-lXtFr-431v54GNb9MN22WDVVzpcTJZqulF42nS52ldRJUhGVvN62qCyyv5tsh4ZyhzAluy5ZLtG8kbMVFO-Lmp7kF5MHMlNscfHGOMoLouV818x68TIjIGQpNM313ieTQPFdaWloVmi4XZPVNe_-jGdrudzd7men1s2aW2Qrzc8_lYewNxPz9bkvTbndyp3Jv3lsH5VmVYrmKokgd_t87ILokTKO_Lx6OV47gZ9i-a3wQ_QitjxCplJOvedl0WSaWU91l6NgFFzvFNuyKHNF-6eKr6CQNNQfgjnTo4PoDubn28oxwurscn92p9I6AK2-R5Mqjejxzy_T_lZtmVBJYSjjUa0WTlILrXzN-U9r8iuy1tNad-WkraAndWle6K6_nTYnhCwhXStcLkKOb926n0RuLclbzI3PCrshDBgIcPXdYL_408ZVYf0KNzYSVzDk9QkI8QUxfj-26JWhQSdwe1HeuAhfqEQImWH3Zs6NrC5Ohu5T8G5uW2WfJVh-eKRiqi5iBkLsVDUy1q-MfdYJb-pPAHqan5xt2AJBWw7XTic-e-KWpqxiJMxc7anjkzeaPJdM_dEEwBAemIXEg3XaYlQHCLPu-mEt9puICuuIlQ54wIduj7N4v89m8IwvjjST_2192Gxq5d0KWKGD27wde1s4AxsNKO6g3eustJ_XkSIxF22zivuwrZEt2U31AeJ5F896IdGV7dTyv_Bx9dlMKXKlrAu7xEnZeicJLv_nFqk8TMv_xEU0bqtGjkVTf2TGM8OuxBnEkBUVubUt8mM6GYGWAmn2_hehg1I9pm1lmgdqHcR170KnIH094ScaAzawFXiDn8KI0L48xY3LTaUN4EHHxotb6Ax1YL94_UeMsyFr-OgnEB5IJepsIVDOyGEjSVT3jzXuFne6m298xODbLarwIoQ6B.deb5uT1ewwXsSw4uGe_mlw",
  "access_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE1NTM5MDYyLCJjdHkiOiJKV1QifQ..PtOky0Vyoqmo5WIE.1jH5YVB7Czz8VGtv_8DF5JMsy89bqVyu13ksrTFwQP_lx7wVzaxn1mJceMobiIKLoyiBZCITXTpSl4QQf8pnyBgKSwrfdbFddOwRQDUfyFXwIeSjJy_gKs2Ah3ohc-OBVDUMSm_zfIoGSWs5lNa9NBsvRIVhhfJMkPDo9DSSGhr286F8d76wu8lTs04qQg6mUwfJafQXJKT-xdpb163Pfc-3BJcCN-hC188wRrsftgVhQ9id4shu5A_0eux8LPdqP6j4QExX8Zz6PBvYiSJOGmhatOmFboDHGqrG5kdc0-3M8VJyQsfvXdQsm_Pos57AzDPvc_Z9wdfr3MpjLHmz8kBP1lrUtUi2r7HiWWqeYs55Vq3CRUV1EdHrIpQvsNUa3JGlJWmcNcxHR1aOvjVdefpmByj-Ud1By4kthRuh7OA8M--vjjC22WFWSVqJOH1Fya5j77PGDM3n13BX4xim-knyJN95X4j2q0g3ZJGvM3Vyxq1tRJzM_6W3C69bBlyi-Fmpq8vvF368Ekbx860DW8BqNlEwpN6HfQZiVEccYau-jD-43_cXL8YgR9_tZ9i_2xNpBzv7X3y8uloibEoRTvvrdw1eZAwPLOk4M7Km6Tf2sCAPlhAQbHlSobug2tEyOwbnI2WvRD_dZADIkckq3lZVf8P-bmTYVT0CljB99uYiGFPXzCp1WjmERNYABP5IkhVWEWLVZ2__IFWkhmLNaf9EL5__wKRpCwXZyxIsw9-fmp06XoRx0_2jMdhG84ggxbZMwBC_lMDtoPuEHwAr4hJNZWyNIRUalk6QpLJY7OqY9jNMaSK8EYOJMQT-HkU5IJ1icKN545i5iNLU4vj4xYKwtWiyXDRJst1JE5-BeypZG1Fj9r90QCOxCp6BDZVnWoIRP2LBCUcxFENUoJBGvZFH5j7dQvlMbrgcyiNVX_QgjCm0sON1m5qvhz9tTM_GoRJwdDdHE7XqGw-RWPdiRI3-YP4qyeIJEJTk5KxOdsbuDwEvvb7pllP_VbtzMO9Q9rJwkIbTjacSVMot-f0G-gvz3fBtkkKRHzxj1a4pOKZ47mdpbLCGsBAwmGruy2k0n2EiJOleaMKC9QHEsNKv6-czEw.5XVcemVE23BFF2K5icUcJA"
}
```


### Access Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1615539062'>",
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
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1615538762'>",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1615539062'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1615538762'>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '6e0173c6038e104f'>"
}
```


### ID Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1615539062'>",
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
  "at_hash": "<Erste 16 Bytes des Hash des Authentication Tokens Base64(subarray(Sha256(authentication_token), 0, 16)). Beispiel: 'JXJCim2-CXia8mAWap4Y-Q'>",
  "sub": "<subject. Base64(sha256(audClaim + idNummerClaim + serverSubjectSalt)). Beispiel: 'qDAmiQOl5_rJ5-ok48lbjSs6QH9oya7VuxUJ-_E1HCw'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "amr": "["mfa", "sc", "pin"]",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'jnTKmBdGCITCOfMy4Vgh'>",
  "aud": "eRezeptApp",
  "acr": "gematik-ehealth-loa-high",
  "azp": "eRezeptApp",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1615538762'>",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1615539062'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1615538762'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: 'c86f8cfee4767944'>"
}
```


# Discovery Document 
## http://localhost:56103/discoveryDocument 

```
200
Cache-Control=max-age=300,
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Content-Length=2619,
Date=<Zeitpunkt der Antwort. Beispiel 'Fri, 12 Mar 2021 08:46:02 GMT'>,
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
  "auth_pair_endpoint": "http://localhost:56103/alt_response",
  "sso_endpoint": "<URL des Authorization Endpunkts.>",
  "uri_pair": "http://localhost:56103/pairings",
  "token_endpoint": "<URL des Authorization Endpunkts.>",
  "uri_disc": "<URL des Discovery-Dokuments>",
  "issuer": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "jwks_uri": "<URL einer JWKS-Struktur mit allen vom Server verwendeten Schlüsseln>",
  "exp": "<Gültigkeit des Tokens von PT24H. Beispiel: '1615625162'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1615538762'>",
  "uri_puk_idp_enc": "http://localhost:56103/idpEnc/jwks.json",
  "uri_puk_idp_sig": "http://localhost:56103/ipdSig/jwks.json",
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
## http://localhost:56103/jwks 

```
200
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Transfer-Encoding=chunked,
Date=<Zeitpunkt der Antwort. Beispiel 'Fri, 12 Mar 2021 08:46:02 GMT'>,
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


