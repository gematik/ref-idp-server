# Basic FLOW 
Log-In attempt using egk with DN 'CN=Juna Fuchs, GIVENNAME=Juna, SURNAME=Fuchs, OU=X114428530, OU=109500969, O=AOK Plus, C=DE'


## Authorization Request 

```
https://<FQDN Server>/<AUTHORIZATION_ENDPOINT>
    ?client_id=eRezeptApp
    &response_type=code
    &redirect_uri=http://redirect.gematik.de/erezept
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 's9r1u7e3M82edpUMvDRw'>
    &code_challenge=<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: MIF5UYSJOwnxhXEGvuXEZHQwSbrRbg0pErplujHxYm0>
    &code_challenge_method=S256
    &scope=e-rezept+openid
    &nonce=<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'UschNhZc8AHNSrdU9x7X'>

```

## Authorization Response 

```
200
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Transfer-Encoding=chunked,
Date=<Zeitpunkt der Antwort. Beispiel 'Wed, 24 Feb 2021 16:58:32 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "challenge": {
    "rawString": "eyJhbGciOiJCUDI1NlIxIiwiZXhwIjoxNjE0MTg2MDkyLCJ0eXAiOiJKV1QiLCJraWQiOiJpZHBTaWcifQ.eyJpc3MiOiJodHRwczovL2lkcC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJzbmMiOiJqeG81ckZkYXRoZlJPQXMxdzdwWDd0YmMwbnEvNmxvcWpZb0lLZ3Y5Vm1jPSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJ0b2tlbl90eXBlIjoiY2hhbGxlbmdlIiwibm9uY2UiOiJVc2NoTmhaYzhBSE5TcmRVOXg3WCIsImNsaWVudF9pZCI6ImVSZXplcHRBcHAiLCJzY29wZSI6ImUtcmV6ZXB0IG9wZW5pZCIsInN0YXRlIjoiczlyMXU3ZTNNODJlZHBVTXZEUnciLCJyZWRpcmVjdF91cmkiOiJodHRwOi8vcmVkaXJlY3QuZ2VtYXRpay5kZS9lcmV6ZXB0IiwiZXhwIjoxNjE0MTg2MDkyLCJpYXQiOjE2MTQxODU5MTIsImNvZGVfY2hhbGxlbmdlIjoiTUlGNVVZU0pPd254aFhFR3Z1WEVaSFF3U2JyUmJnMHBFcnBsdWpIeFltMCIsImp0aSI6IjViZGM4ZmM5M2Y5NzMwMmIifQ.BAsiSokMozWXqDA8tYZz6CE4DPafbo6etIF7oOTyCyp-rbTIn0_UjRn1fmi1H102Tf7EB699e_8Ezp683iFsqA"
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
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1614186092'>",
  "typ": "JWT",
  "kid": "idpSig"
}
{
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'jxo5rFdathfROAs1w7pX7tbc0nq/6loqjYoIKgv9Vmc='>",
  "code_challenge_method": "S256",
  "token_type": "challenge",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'UschNhZc8AHNSrdU9x7X'>",
  "client_id": "eRezeptApp",
  "scope": "e-rezept openid",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 's9r1u7e3M82edpUMvDRw'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1614186092'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1614185912'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: MIF5UYSJOwnxhXEGvuXEZHQwSbrRbg0pErplujHxYm0>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '5bdc8fc93f97302b'>"
}
```


## Authentication Request 

```
https://<FQDN Server>/<AUTHORIZATION_ENDPOINT>
Multiparts:
signed_challenge=eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiT010a1lya0k0WkJhRXNOeUJwVXNLZEwtNWhINlNRbTIyT2l0cEJVazQwWSIsInkiOiJTbjFRMF8tUi00T3B4WXp1Sk13SjYwSHRPOWJtRHRrcHdnYUE1cThkRDh3IiwiY3J2IjoiQlAtMjU2In19.qZhl6m-wIhx4aM_idiyHMgrDx7VfDqkbDks-9p5ljKD5HHQTdD3Dgg.gkXHFMKJ3eAHnQq4.MKoYoPJDhRUpUFUmq--FMHTRRZ26JQbZCP8UhPYxcunLdGRjIMBqG0GgNpcZLXH9Rd-wrvgGrUutZ5BhdPpPCihEy02AtsYoXZMgnxj46w-KlcnjvcncdeAuX5EkGpY1HdA_B3C6OvEffdYdj09MK6WkdNbONfLdtoYs5bXl1FsRQ5YoCu1eVfHg51aE-8dLLt8iJIANZapunSPtywCDiiX_vsonOroH3qjuwbnPgpNXDQ8Qk84kC2PNTu2kkealSWlz2drO2p-CS2n2sp5_cmhtvC8HcJToU6yOu2E_yaELaicIRllCHdP2eh362lQaNsot5pEvNw0OcjROOTs79UbHuTqZW-_GOZr6c6mnyymI0cTs2iZeQXiBXRBDwVSx4xpi22nCAgfmBpZ-At-zMo2f0A-yXsXNTF8XOj-mK_jMp_l8D9RXmR6z4tblpyzIg2klGtN1SAVSOoh1ERNJN8MtLQOn2bocgdEjeDOwq2hT74_Hr2Ir8fJHZXr6_E2A_tv7hO25zntERn9zRUc1XWM1iB5NjzR-z51RqPQbOXqPOeRhdCvomak18l2QkPO4XL9WL_Uql4VfXuxgFb0ivhxKZ_Xr8n_ZLNhPFBWa6P4yVzI1oGJyu9X_VLlMxw11OpL6lSO690PUCslqMNZZ919pOzWbBUW6i97GeiV313RmigOjb7cWGztsU2WzJ0xtXlzIAo7YF5EGubAr3cIi5TtmcZ79ocK67LD5Y-9PIGb8MtUb39cyV-diDJV2wpp-tDGO7IejG4oBl6BPlXJSv86IdcRLJ3Q4-m_0TUV1rKYGyW595Doxw-lgsKD8d7WeVv6usaPWA_TR84J2XliIlV0hnANvf8eYy11M2GxvrzhueN7aJk-0z4WdX_VQ5I95mO-ureiJeGNI4i0YubPn7g_GiqB_icH2McVdCVmiY9WR_VEA53Ym0iS0KCq0edpW2nBQpHkkibb2WtgOmoURSld1LxD1CDuQMHGTGEfFVRE9yEqjPhEWPXgnXxFJVn2S6h2bZrESCQQQVMBEfxy-Xab1RHsn0Qk8JY7LHj4egziP-G_F8j4oHdILvJHsJ_qY-t515Qrk7x9dFFPvVrfBA25uBlUx0XDJi9iRvO5u37mzVQHB7rJAb1LX7HAScil-8GL3cED368BZeeqlIYmXHYeR2Rd7oabeQO9SmxERCocrttIhPCz3osV9pMZkjTO628sdKB7M2TtXQ4jWFMdjEvZtRcs1zF2g9Em5cN7bwUvo2iDKJzB-vNnUZAqwyo0jZRB0Yiy6c434biNEzWDJPChKXD1b8VLvJJnvDf8R559vc5h3K9YTlUz3oLT-ISMH_RtTh-AlBSwHNy2Ro7v0tDmoIapp_ufO3y1hKUFiGZV5kNGYzOH-sn-Yi51RnJnz9t8okzAjShVQl5NGjdgzSm4vKfnO4ISisCAika-qQuEppIHyFgtcPMt8eDRGTce4D480MGWAXSyVeJtOCMwBoOmpqEFhhQdbRGEuQw0F95ojgcXbbU8zkWYYgovRHetftVUwVC0T2uVkz9y9Meoj07Sh58_eAQ4ntesEMA-iz2SjpRlp5TWdtoDUHzbJi4IgoQURhONQkdpeSW3OJZy8-FdZofILCLZnMG05D3fPZRW2psjP_dgDdgNY562H5f4FmSb3poS7IsG9ahDNE8Jkh7_M4l7grv0dIuRzrppmViMRtr4rpsRhaga7zT5mpmtl2UkZ-t8hHCmFyrVrfZjGLiE-FT_EPzHFbdGB85ggbc12FKnPJT2d0xp2E8Wy8rUlDFSUiclVTWHnZI9j2e0JvWCYce1EjvqHEG3W-Hz_MsGalJYppd2PoBZExyx52WJCOtfhvskOtNbmG19zxAqWv9RhOMWFDKYUNTKuf-WeE6qlNnmz3uruLPNctn97MMxGYnfRI50_tU4wJtpZwgoxx7yI-t1ndg6AelaA8gyIZy2F936gk4Rm26p0fBaWriVgo24W7ieX7gsf3in4a-JnpoBwz8FS2C_B_E3tcGj_enOsI5jm0UCMrkHM8x4Yh-eylYK_onhUnorO_hvgr1uTOnYHkvflyVZCE24uD-kNq1NhcDU-d_AVJTSW9Fubko_9Ot01tXTlxCPsPEXjekBsyo3Wx-r27Psj-g7v9Z4QEKx8Huh_N9o-8780rYgic5izetTwIuCKyqEZba7t_asCssbfrrxWSZzw8lkzeQSQf0tK9w6Hg6bIAanTD2gDDuQc4Lv3iIZO6fDSGxUmuL4HcWEgpxCbIiLvgdpcEP_7rkkPVB4gfHJCS7i9A1svoyhmgeV1ftebHUij8h6PUV3IFnUe6MoKHYzKnvGDS1lt1qsxGavigUVlMflPP15G8S2D7eVxshrYq-6-YfVnu3I_2nW-oFj_Wk7SocGkRLJRjxewn0DKRBVF2gmJUilGyTUAXXaywcv5KjUaqtQ58WYMnIEcbldpwK29XRyF4b5etWf327kqzaRKVfnerdcuVRTKC6qv7qq2VgzHDj30jjJ0ErXB3pcrE8pQ_zXZpUdYENQ58mcwH5i4wczXO8ciVGWqF5Q_Zgnngq_c-F6i0HseW77FyXnaxezzm-lwmlAaAkFEMVGhXpFbbkfh74mhNi6xhHga7cNPPe-UNtbPMVwCXnzqV02xvNK5sUHMZOltFXUspNDCgKjBxiUl0lT3nmpMnBK6WFZRaZGjL-kPpLoSwagHmdkBAvkfS0FsbttNM-AiRRGcOl_HA5UnjVr7ELgBPeWDjlSftmQduvCdjgvoJxtWR_HZEZpTMv8YbN3I9K2ybifpZb93gz9i8HzZQHweSD9Mg0LoECPU8BBVYlUKgvvhucS9jg2yHnryjO3ns2Fai6c4CcOM23BCKo5jDZLvf8l3C_eZL53Suy7kmgAVzcY8MCtktSBgWpK50Fq9fQz_HhkNj5HtCR8phCb71eIrSmtnUmAP-XsxcuwdU1Vpg808T2hUTNCa7Dpn1j834d3O6mYUnYOnCilMHcb0dFQpISXAd2qXusphBHTjToBqCUzAl2wMzJbCPzp4ka-LKMqzOGHbmSbkzOBFy8IJ-84hnByQmdtfHb-ry1TBVLwHCFv5HKabtUniacSaEll_NfAd5uu1nvq3gbet4g6l9cTck4pVPse_p6LAffv6M8uHrpB3jS_hikpf_z1ceXM5SJENWAR-edwFSNBYjHRh6_wZ94YXbeAWw6NA52zEK4-oHW2E20NhEDkDL5msNMuw3OgFKmy5yKywVErtZvARc4OdtUcj-VfclekWwBk-HO6vyyHcFYjzGP93XsK2tBnsMonPwNywIU27JYIF1Zqrel-nn0beRXu9DEvuyC5ma02Jm-kpgGRCJXug1gV0R6i3NarH-RCVpqw4UnutFqC0_tyrPwCWF8jO_pvpi1A48Ti7UImISiPQe-mSxgX1Tdcg_FeI5GId_q9jeO0p7Qo7KzbNmHZ_h6tuIPxYfX3SUZ6aLNtdeA.3uEAn1U_SHNebHsOJY3fsQ

```

### Challenge Response (Encryption Header):

```
{
  "alg": "ECDH-ES+A256KW",
  "enc": "A256GCM",
  "epk": {
    "kty": "EC",
    "x": "OMtkYrkI4ZBaEsNyBpUsKdL-5hH6SQm22OitpBUk40Y",
    "y": "Sn1Q0_-R-4OpxYzuJMwJ60HtO9bmDtkpwgaA5q8dD8w",
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
    ?code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE0MTg1OTcyfQ.._uNRw_VrthpiPeOp.HEU14lWV5FWyFXMnNFO-JUUUbVDgLir7FGxDWIBRnzYbXAvtzEYinPTvu-kgr-JpZyzl7IHwGO0mRQ7-cDmoXgqyf4XuF_KeOunRTQ3ZFq8Vo2oNKvnABN9vzTWur0sZ-MrdxxqfJcvo33rd7Dx4n0afb_ZElLv8HIuhW3HqQH682ZRtpfl8pHxOMiXRVlXYzR1-YY5iLycyrvYL2X3uB-3AoiHE2crXkGoFKsaDVw4eLYbJWQOo3P8uGcW9xpd5NXPzc6G_9bWDlJnz-R5qec0nt9dMCcj67GAAhwpK9kpF2JTiXPhe0d40NHS56MAjeI-awEmzvaE6yAQuu9P9eYuVEeHOFUzM5prVCpNw_k_Y8WfVeHl_cvbUGDk3ajLPJbqgakvFwX0WMlVoCoAsj3qPVYvRdinmaOBxKFgdkeouB8gsVC7DDQHIeLjVRY9BgnHX_sBmzmoAU3OrBBcqizgiykFUYcwNG2JbQAXM4H0jiCmlPy4pXev0kWfPjGlIOpqT_Ipa5l3VHgT5Zfaoasx2SHiEqT0MJJbFmC9o_3Z2eAAdKuSd_ZdzyzZU0TgaiFxIfCTTVC6k1RvzFsUBUglKxYnDiAE_eMf1O2_o7MN72t-RTEumhYPxJQxCFiD2OfI4FRri7tOmQ1DUXum7U8SHaLC4LClLmr6l8qmPLA2l7ZF8qyNopJWrudTgmyXee42DDekjRDAxm7ic_owrQZ9OLhHBqiYVAtopzvZUam6joCfqIu7Zq2iJ-7MwnQgXX7pm6rpGse8iQjfkY9rMS8w368ca0-oQlwyMXzgDll_ZUu4pdB7ZkrGzRUcPKa1Dk0k2q1Txap-3P-CQDdv6Ewb8MOTlmZTkhpWxrpksd8uR-jBzABmXp6I31LMboCFtbRmtnhY0y3cwfxzSzx5d4asy5K_iu1Ji2S4DHsY0ZcD_duUfBi3vh8EJPEmRWVDoNH_KYqTFIkT1xEv6WOa7h_OjW18ykmA1NcTTKST8PF8cCNLmnGSlRRCg8ezTStfNF_aeOk-0pEJlKAbtbMvGMdgjo44MQPGU-UFyJxadVAAuNRLi8rGRJx7TPeqsVJc4xTmJcD4invI0OMydnU87GbZouUQPSZyKC5VsmzqiO7fIBRyTjx9dYqr52o-1KLiC7Mi2fi0ihp8My9hjZmWAPZso9oJnnXEracJRzSFFyDfBsf0AqsPzqlpErREqgrL9xPX37J9Xyl8quztzUG2hxrsjx4h25j9cBUWTqQrE-KPG8j3opm_Lp-tgKbdKRhuD3qqbVOqkK19Y2-3ip4lkTKZxOEnG_4qMPv82BbrJSLHVNwJgfLz0Xfj52QZNAInAkq4EeOo.hjfqU8AJcEw-exoyu1uxUQ
    &ssotoken=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE0MjI5MTEyfQ.._DmuthavdC7vOyoh.tV_j0U-kIhVXGm9n3rCUWYU0Mw1dQKtpgcuXQYdPUPNsAQdpr8uchLPw58TZkvwM2jC85SlSEgDJSKtom2y436JEfxt9oS4Jn6pZP44G8J94hHCtihp6fBQdydJ-tuSan_ERFLToB0EujqzVtWrmpZVqUKuKUlzYnOY2bmjpXQprF7Cr3Ovt8chOU6tJYDQefKNy3s8hzVvPlSc-TNR_ekXtQULTkdAvqAqOCGEkGuVZMztN1MATO9J4qMN3quEJweCL_TFU-e3IxpIx_EFoHvYVIMqD3pMY8URfAyiuv-btIt9zrw43snybtdaCouutwTw6LabhLhwAsGUURVnfI_g841doJDGVj9qkvqzvwA0StpBSLbz8EW-v0jJgr6eM0efo1bEeQKBxW61fQoEyFOKJgdeoLQsCYTZz_Smu_hFd0eM0BNc9dhC6ONrNp6N90N1qOYZV3jvU92CKKhbcbOzqP2ZdtNgft315ug4gryzVsoRw1ETf9to4BBbE20Eirsy1TRtQjxMJHFRsMpuejndPGqFmF-ltDLZXhyMgUnlolww_FgLoDVkc0ypKzjnr9WgAXv2-svinxK5_w1i0wQ2gpGekh1Kl7QsK3tfXW8rO39evnALaEXf2Jw3TJqPsAW2AMHMSi2OgF5XgwWa19IStqgpqhPCF8ESoZ4MPv9zk6HBUVvh43_cnDsILZZ9slvH91dC9VvMfTqdIiP1JB94zRGs6LZbFUOx5AahXW14cM0h4B68-lisa9H7VUY6dL0Iuz8DZFxHXbV8hsna_wy_1yAmGHhd5uITHe9e3_nGRAO0VDE8m7GKzY9BMSoCgkC5iAGxwzA6hoYvkhMQQnaI7UAvHQFhSD-2sy0FXJjnScfQkua3xk2BYWgr93BGJy_KFpsJqi9l-nCzzeAQAooY7B0MeCyPwmKGIvQfiRJRgODnIhW8I6h3vuPnfrN6OGKbXQZwvccaYp_E_YsEhZoSo2K48CN6jHnz9B81zBMtl15uZE5vpySyECIE2I2HEDM9knF6imwg24cRkqnmQK2eVc_6c2ezrzAY3x0qFmbFNdCW7wBHeIDwruVCrnm1v9xQrpjBwBCiaBpgCTZOGaBUHWrMKDRhRzyNdfQ92LdUufdBRFKUbht6M9CH04-5xx9FW9_GrsOWMt8G4ZT_QH5fA1rDACK2ckYKvIsWoAe32yj3VcWkW2pXXrrhOVpxODlV1x8D2tgfp05C3jruE_9r3D7V-yKXEAzAu7MaUqT-d1OwiSJY8p0Yy3blKlUsl9jIs916XYsq_j0sDSDzP1T_XMKcK7EKbOqXGxOBx3tyZp-Wt7BJejaAZgHbKydPilu-ZKuG-qPPToYvrOqokwMqEYTh97HHuzxTRTRuMayGMg9oG7CuWBBjtO9zd7c1ZATKdfzy9WkVIE6sT_nIb5DmXXfF2hILfZ-cWROPWkBiKxGFmcwQhTncu22e8eI1RuqUtfHu78S1-idhfNBlE8ChlRlnSZsxoIBsP2jQIlcOKqIkzD48rPLaNlb-4KOrV-g7M0T0c_vDtFNHflsDe0OINgVIZrS_LqSfAUzpqBeNOTaRK4QfHWKe0XAVWZqVls2e3O1kDVScPZzHPYewaGlLCZy8zsQf7at720knJTgK420pKiCmQy7bklhArZorZ0cDAIpx7VQfC7UqgfjvlHZF5qld4CPcDoOX9J186vKLwt6afTOM8CVu1DVh5V5SiHk_OXWY54OHsbzPeGadIXZrxIgxPEMzNoBSSvFN2rIetKA-gc7Dhhb1tdFUQTL2wlC5PqkJ1yXWl3Aga0RBOyv0G5gcbk6yeujOJspC0AZpMm2i_Ry4eZgVAqJcslwbSFBUmWcq6E9LHwN1ayQPPa4ZVlqarGjesQFZAv-FuYRVec4bee_GALF05Nw1FjtKWRh8uD27UXwYPSMvBUQ0MMUXNc0uPytGNj9pDZWW5PTeaVqAR7_x1M5vB35ZaKzc7jJ0SkpSuCL2dt-xeVN8eHEww-6n9ilFQDWvHWfAmpLsFpxDPPN0VQmHrE8m1f8pxf0JT_Agz2eVow1NhVumBSqB5iBjoV--y9wOcZnhbHpa7cUxcSO0v57eg-gMRhTnhkgniQYmCH0FZbq7-LieFLVfWQmch2EidrbKCFXO_OyjoOxtDQpMBwcaVD6byDQZMfnDVWqLfZn4Mk9M8_rGqBJdGmnqWIeau5r2nU4LXVxG9iZR49hCdkq9YDpnW3pYrFUWUHddYT181E5AiSXordKFqz4ViKFClrkSuL50g4NLtv5CvooC9n9uS_kGZm0-iEJdEt767O1Hqlzkp5PpLgPH5tISmqtqSiH52R2ATX68wCCVgZdJigicrrw2V49AAdCYmG-znRQBaH25rb8TA7LR7XUmYc1aR2teuRVl1ISwid5z8ASfuzrYatYAPYy3E45MFiY9CPtLBufUIQIJLauxxZH5yRKqJrUVKpTxm2pCy8ngUhX5EaL4i0XwsQFCyPDk8X71lrRtGHRqio8tbdjb_VrjDh7aZHqkByvrS1YRpLH9OY6PqRxgC0bTOgO3YuX-5y4y_b9erI0V7SpblrsxxEO1xXv_WV2E65kNKEuH_fX3Oh7cfGnTLM4NAg6DzEqP91tIphVMxI8YHyhpQ1j0pFAnIYfddPdw3UOWzvc1aQaaG5JfpsAXRgrEoRXCsQZhejaGyUDHzEH1_hGzrD4Reitp6yQHOWC1pQfOHlwX4l5toIoSx560iNjA1eKyr5Ck97n3szQkSqnD7Zmuq3E_RugcVpztLJb7hz0A6CqjNYnzxMEgFK1TysHJuAViVR0tr8iGM-8492YGIYEThcWaKnKw.RGe5IpIO1i-9ua7NaACJHA
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 's9r1u7e3M82edpUMvDRw'>,
Content-Length=0,
Date=<Zeitpunkt der Antwort. Beispiel 'Wed, 24 Feb 2021 16:58:32 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


### Authorization Code (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 1 Minuten. Beispiel: '1614185972'>"
}
```


### Authorization Code (Decrypted):

```
{
  "alg": "BP256R1",
  "exp": "<Gültigkeit des Tokens von 1 Minuten. Beispiel: '1614185972'>",
  "typ": "JWT",
  "kid": "idpSig"
}
{
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'rV9cGvp1ac6VlDssvjKk'>",
  "code_challenge_method": "S256",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "token_type": "code",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'UschNhZc8AHNSrdU9x7X'>",
  "client_id": "eRezeptApp",
  "nbf": "<Der Token ist erst ab diesem Zeitpunkt gültig. Beispiel: '1614185912'>",
  "scope": "e-rezept openid",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1614185912'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 's9r1u7e3M82edpUMvDRw'>",
  "exp": "<Gültigkeit des Tokens von 1 Minuten. Beispiel: '1614185972'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1614185912'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: MIF5UYSJOwnxhXEGvuXEZHQwSbrRbg0pErplujHxYm0>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '46181612a3c93501'>"
}
```


### SSO Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1614229112'>"
}
```


### SSO Token (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1614229112'>",
  "kid": "idpSig"
}
{
  "nbf": "<Der Token ist erst ab diesem Zeitpunkt gültig. Beispiel: '1614185912'>",
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1614185912'>",
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
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1614229112'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1614185912'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>"
}
```


## Token Request 

```
https://<FQDN Server>/<TOKEN_ENDPOINT>
Multiparts:
client_id=eRezeptApp
code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE0MTg1OTcyfQ.._uNRw_VrthpiPeOp.HEU14lWV5FWyFXMnNFO-JUUUbVDgLir7FGxDWIBRnzYbXAvtzEYinPTvu-kgr-JpZyzl7IHwGO0mRQ7-cDmoXgqyf4XuF_KeOunRTQ3ZFq8Vo2oNKvnABN9vzTWur0sZ-MrdxxqfJcvo33rd7Dx4n0afb_ZElLv8HIuhW3HqQH682ZRtpfl8pHxOMiXRVlXYzR1-YY5iLycyrvYL2X3uB-3AoiHE2crXkGoFKsaDVw4eLYbJWQOo3P8uGcW9xpd5NXPzc6G_9bWDlJnz-R5qec0nt9dMCcj67GAAhwpK9kpF2JTiXPhe0d40NHS56MAjeI-awEmzvaE6yAQuu9P9eYuVEeHOFUzM5prVCpNw_k_Y8WfVeHl_cvbUGDk3ajLPJbqgakvFwX0WMlVoCoAsj3qPVYvRdinmaOBxKFgdkeouB8gsVC7DDQHIeLjVRY9BgnHX_sBmzmoAU3OrBBcqizgiykFUYcwNG2JbQAXM4H0jiCmlPy4pXev0kWfPjGlIOpqT_Ipa5l3VHgT5Zfaoasx2SHiEqT0MJJbFmC9o_3Z2eAAdKuSd_ZdzyzZU0TgaiFxIfCTTVC6k1RvzFsUBUglKxYnDiAE_eMf1O2_o7MN72t-RTEumhYPxJQxCFiD2OfI4FRri7tOmQ1DUXum7U8SHaLC4LClLmr6l8qmPLA2l7ZF8qyNopJWrudTgmyXee42DDekjRDAxm7ic_owrQZ9OLhHBqiYVAtopzvZUam6joCfqIu7Zq2iJ-7MwnQgXX7pm6rpGse8iQjfkY9rMS8w368ca0-oQlwyMXzgDll_ZUu4pdB7ZkrGzRUcPKa1Dk0k2q1Txap-3P-CQDdv6Ewb8MOTlmZTkhpWxrpksd8uR-jBzABmXp6I31LMboCFtbRmtnhY0y3cwfxzSzx5d4asy5K_iu1Ji2S4DHsY0ZcD_duUfBi3vh8EJPEmRWVDoNH_KYqTFIkT1xEv6WOa7h_OjW18ykmA1NcTTKST8PF8cCNLmnGSlRRCg8ezTStfNF_aeOk-0pEJlKAbtbMvGMdgjo44MQPGU-UFyJxadVAAuNRLi8rGRJx7TPeqsVJc4xTmJcD4invI0OMydnU87GbZouUQPSZyKC5VsmzqiO7fIBRyTjx9dYqr52o-1KLiC7Mi2fi0ihp8My9hjZmWAPZso9oJnnXEracJRzSFFyDfBsf0AqsPzqlpErREqgrL9xPX37J9Xyl8quztzUG2hxrsjx4h25j9cBUWTqQrE-KPG8j3opm_Lp-tgKbdKRhuD3qqbVOqkK19Y2-3ip4lkTKZxOEnG_4qMPv82BbrJSLHVNwJgfLz0Xfj52QZNAInAkq4EeOo.hjfqU8AJcEw-exoyu1uxUQ
grant_type=authorization_code
key_verifier=eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiVTdOMzRiajZjN09LS3Vib3JRZzdTNHM2aDVLXzIwVXFrR2dDMzV2cjk4USIsInkiOiJJWVBIWVpnMmhXLWZ1N1drQTFYWkxzaDlFR3h0cDg3ZmZWNld4dEppbU9BIiwiY3J2IjoiQlAtMjU2In19.tVlblVJVc7TWX9hqkc_MVhAGxhPdp1TiAolBbjtGU4K2G3ennI7NKA.orHk833ENAddeqUr.R2UENotzTbVg_88jRuQ4_e4N6kJqOEGhuNnZNEvZ0iTej-ev-T0Uy0DGweQHmOU_FUY3udYtvsRbuYrtARfwwsjIHE_sSc4yQDUX-lZq3Onnszaz6LDmKXKprCtGFL3PH2VxjETxpleNYhgaKropG1fKHqiXTIIRc4Q.cRMHZm1O23nB6IrZZFYl3w
redirect_uri=http://redirect.gematik.de/erezept

```

### Key verifier (Encryption Header):

```
{
  "alg": "ECDH-ES+A256KW",
  "enc": "A256GCM",
  "epk": {
    "kty": "EC",
    "x": "U7N34bj6c7OKKuborQg7S4s6h5K_20UqkGgC35vr98Q",
    "y": "IYPHYZg2hW-fu7WkA1XZLsh9EGxtp87ffV6WxtJimOA",
    "crv": "BP-256"
  }
}
```


Key verifier (Body)


```
{
  "token_key": "SVdmZFlsbzNSUlpEQklwcnlpWmlmRVN3cXFBbkJnZFM=",
  "code_verifier": "XL-DREFg5rEkM4nly1We4M0BY1eeasWTnJ_h6kFW81k"
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
Date=<Zeitpunkt der Antwort. Beispiel 'Wed, 24 Feb 2021 16:58:32 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "expires_in": 300,
  "token_type": "Bearer",
  "id_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE0MTg2MjEyfQ..JZLK9oFYhum7_jGj.H1UIv_qHRucuZuya9lRJYrucDl42SxwB8OyhE7nEr_wnY52JYnhYqFMUCFXBNIc7c_FGYr2qLUXuyjxeHx90UYJpHgK72_KyXFu5N0Cx7s8smtCW63eQUgsCScI-LEssbN_Q6GwdXcgq7hU3mpak47TIMU4LzFWPNBDAyf29w0_AvwiwULZX1FIh7W28UsSHD2s-6ePJHYeG2QxJMvpvQ8eDnMQssY3QeVgjhhx-pA2pxytlmZRcfhB8bifSGGN9hLHo0SukVWHMbsWWQMTjQpRaaP6byCjLXxij26YMbw1WG-8hpP7QG0RTb7DTeKex7Uea-L8zrC8CQS0Y8cO7o-qdqEQBdNZBYQjv4aka9hMUKGbBVXK0BIDdKXfPwVlXAVmjnPTedkEVp-D_rR_ay4iGWcXTdOfiz5gW6qBIlVeQJpjHuC6Sbs_UN0Auf2ngR6wEfBCo7irNyFIJ4-GPAB-pn5A-7yH0hemk00RE33INxnLb6N9bERYsuv4_A9TFEOd272e-ORkFlU7k9NwETDmgIdLq6tx0KA1xh1rVAyy7vR1kmGDnf7k7awWELGyTXqPXrJvzkBhwP6qTsAxyKbzDx8L0EKq5EbLcvxGXjUKF4Vr2Mu9SU4PdMKPQumU8d60us4yYIxgRZxGFVn3z_pfpO6GtQJ7WlRKzLfZ_PcKfmfkP4VGHEyQuPy-x2TfqR7F7ywuBUuG3OWRTDqAQRwl6_bUBXLxLFTagQ4IcNbGRXCjYytR_gvtmlQtf96CCBoiPlipu6RIpNYFiGaHy5QJYfk_oOuigKRDC3BJtGEqepjVST-kyejZC16PI3CbQX_Qo6H8OC0R6am9tPB-aqzBlgnEFHv_O3stdBLKxFflF2xgxryISRyt5g94ly94NdYaABoDW_jbj1ny_-_tTBsvRovxXfPfzH2IjJZEOfBZlEsG8eVz-9lKvEQ3uUMcecc64otqsOm4yoJV4ws4992WOllbbPP-TFDaD2VgZLXbEd1rbwYVFrzLyOXkQr3bCvgYe7I96zuuLou2p83N5MYYbMZzoVMSTIlkLCIIV_JQzQ8R_y7vjArlEMg_LWNL9FA.IWYjfMALtWWiA7g1xsWx9A",
  "access_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE0MTg2MjEyfQ..e-uwpSmiv0aw-7vO.ckQ1ZBQyXz76oLSbdtnGGrGo4aqCjcUQx4itra4w6IVbL9NkbEE8_HcgBK3Nkjag8sE0FFX9JEr1Tlw9mYHte9gk0dVvDXe7cHtnCXQ4j0Ct_Fz8ALYR6Q-b722Xyv1y0GEMp3wjAzYhnhNzXDUXB1quoLkndvjdUsGl-htDB64vWAdzKEiK4QIvPWj9ogVHA8rFLc6ma2c8VxfddojurNZU3xyw8aVk1VzM9cIjJaETmKniwR5m2cR85DolcRp2TQZbAzCdzgH9Ni5y59MqmD86ZOFtljngCRmyAozVFDjUe9_ZmvTZA3Z3odcbtequGzBsujlG8sxgAeFUHIct9PvHw5NGkchppXPXxqYPKc78ejAtEYnMExc35GWO61AlHg9irmbYLgGTSZCWHO9k5JGk-9SvPZ6IIM5d4WuC22pJlvkdSKZOb2AF2q3FGG-VXxFo1UH2y6MDxJVMwbaBS-frQgN3h0TTSqm91QQsbR2smqKV12bjcRsOXaN9f5ykD_Lv8Afge7yEaHIYbcRfgxI18XODCXOXsKRts-tWiqJ23h44dwuPqSwnIPMjabiUiZDYrxmvuq_MaMlVsIqGzPcjBewXQd7nQ84M2JdV4QjcW6gFzSPA4tqgA6rPNImgbkspRi3LpHn9XRIBI8lkrGkxTmnO3ygZFvEKMxDBm6aGmgH-9_I5AC0Qfl43gDd4qeuz_mJS_Eos5zecGaxTijOixXccojepl35T8I2aGrIb6VscYMsbLUNRDSPdWJ-xZm6vK07DZYU1jrmmFOVLECv6O1LMoi8UUpuNU3GWNLNvHKR7D0-qeTfFaQm5Au2vVFPch9JMGOhoAzy-Thr5WIJD0m5JuDljvJaZM3-7rrYGZJHypt8cAGJg_C1BKgpwJBwhur8-b6f911kgiEt7yqWfMEFT3fctolk1UiQsaWF_f0wzgHsclxbNyTP5AEp492PpnDHCI0hgKWfhskW2htlwU2Q_HwDxEQE79FSzq2187QCt5IAVmG742osLcFJYTBQ6iFQnYwO9XrZGAfthwUoZDiDuebAIv_GgeKdAx4zGyav-PaUSJnfOhfoaRzx-Yy6ZB-7RkCTdRHUj7IZVLhJUZA8u954jtT0LpYVSIBFJli1kqhQshooJ.BNYIrYvpapbVI1xQmsvZbA"
}
```


### Access Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1614186212'>"
}
```


### Access Token (Decrypted):

```
{
  "alg": "BP256R1",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1614186212'>",
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
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1614185912'>",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1614186212'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1614185912'>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '77cf92b2a44f7fb0'>"
}
```


### ID Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1614186212'>"
}
```


### ID Token (Decrypted):

```
{
  "alg": "BP256R1",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1614186212'>",
  "typ": "JWT",
  "kid": "idpSig"
}
{
  "at_hash": "<Erste 16 Bytes des Hash des Authentication Tokens Base64(subarray(Sha256(authentication_token), 0, 16)). Beispiel: 'TmFnHXpAjCSWJk/mol7QOw=='>",
  "sub": "<subject. Base64(sha256(audClaim + idNummerClaim + serverSubjectSalt)). Beispiel: 'qDAmiQOl5_rJ5-ok48lbjSs6QH9oya7VuxUJ-_E1HCw'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "amr": "["mfa", "sc", "pin"]",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'UschNhZc8AHNSrdU9x7X'>",
  "aud": "eRezeptApp",
  "acr": "gematik-ehealth-loa-high",
  "azp": "eRezeptApp",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1614185912'>",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1614186212'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1614185912'>",
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
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: '5JiRsTifVR7BMpHilsRF'>
    &code_challenge=<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: OD201zCydriS5gPpuBqWjHTLCe0RRakbsU1zr9U4Oes>
    &code_challenge_method=S256
    &scope=e-rezept+openid
    &nonce=<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'i08vQ8Watmhl9DEzzbUL'>

```

## Authorization Response 

```
200
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Transfer-Encoding=chunked,
Date=<Zeitpunkt der Antwort. Beispiel 'Wed, 24 Feb 2021 16:58:32 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "challenge": {
    "rawString": "eyJhbGciOiJCUDI1NlIxIiwiZXhwIjoxNjE0MTg2MDkyLCJ0eXAiOiJKV1QiLCJraWQiOiJpZHBTaWcifQ.eyJpc3MiOiJodHRwczovL2lkcC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJzbmMiOiJBSlRELzNkR1VXVGlsaEJwYXp6aGVYcmZUMEE3N21seVlUek94VGVQR2JzPSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJ0b2tlbl90eXBlIjoiY2hhbGxlbmdlIiwibm9uY2UiOiJpMDh2UThXYXRtaGw5REV6emJVTCIsImNsaWVudF9pZCI6ImVSZXplcHRBcHAiLCJzY29wZSI6ImUtcmV6ZXB0IG9wZW5pZCIsInN0YXRlIjoiNUppUnNUaWZWUjdCTXBIaWxzUkYiLCJyZWRpcmVjdF91cmkiOiJodHRwOi8vcmVkaXJlY3QuZ2VtYXRpay5kZS9lcmV6ZXB0IiwiZXhwIjoxNjE0MTg2MDkyLCJpYXQiOjE2MTQxODU5MTIsImNvZGVfY2hhbGxlbmdlIjoiT0QyMDF6Q3lkcmlTNWdQcHVCcVdqSFRMQ2UwUlJha2JzVTF6cjlVNE9lcyIsImp0aSI6IjljOTgyZDEyYzNkN2UyYjcifQ.GunKRHM4vjxaDaIiaw8r4GHxVk8e-PmEAAk-_1CZUIpXRMRZu1w4cD40iZqeOMlN5v4aByMu1KhO91fgF1oz3w"
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
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1614186092'>",
  "typ": "JWT",
  "kid": "idpSig"
}
{
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'AJTD/3dGUWTilhBpazzheXrfT0A77mlyYTzOxTePGbs='>",
  "code_challenge_method": "S256",
  "token_type": "challenge",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'i08vQ8Watmhl9DEzzbUL'>",
  "client_id": "eRezeptApp",
  "scope": "e-rezept openid",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: '5JiRsTifVR7BMpHilsRF'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1614186092'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1614185912'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: OD201zCydriS5gPpuBqWjHTLCe0RRakbsU1zr9U4Oes>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '9c982d12c3d7e2b7'>"
}
```


## Authentication Request 

```
https://<FQDN Server>/<SSO_ENDPOINT>
Multiparts:
ssotoken=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE0MjI5MTEyfQ.._DmuthavdC7vOyoh.tV_j0U-kIhVXGm9n3rCUWYU0Mw1dQKtpgcuXQYdPUPNsAQdpr8uchLPw58TZkvwM2jC85SlSEgDJSKtom2y436JEfxt9oS4Jn6pZP44G8J94hHCtihp6fBQdydJ-tuSan_ERFLToB0EujqzVtWrmpZVqUKuKUlzYnOY2bmjpXQprF7Cr3Ovt8chOU6tJYDQefKNy3s8hzVvPlSc-TNR_ekXtQULTkdAvqAqOCGEkGuVZMztN1MATO9J4qMN3quEJweCL_TFU-e3IxpIx_EFoHvYVIMqD3pMY8URfAyiuv-btIt9zrw43snybtdaCouutwTw6LabhLhwAsGUURVnfI_g841doJDGVj9qkvqzvwA0StpBSLbz8EW-v0jJgr6eM0efo1bEeQKBxW61fQoEyFOKJgdeoLQsCYTZz_Smu_hFd0eM0BNc9dhC6ONrNp6N90N1qOYZV3jvU92CKKhbcbOzqP2ZdtNgft315ug4gryzVsoRw1ETf9to4BBbE20Eirsy1TRtQjxMJHFRsMpuejndPGqFmF-ltDLZXhyMgUnlolww_FgLoDVkc0ypKzjnr9WgAXv2-svinxK5_w1i0wQ2gpGekh1Kl7QsK3tfXW8rO39evnALaEXf2Jw3TJqPsAW2AMHMSi2OgF5XgwWa19IStqgpqhPCF8ESoZ4MPv9zk6HBUVvh43_cnDsILZZ9slvH91dC9VvMfTqdIiP1JB94zRGs6LZbFUOx5AahXW14cM0h4B68-lisa9H7VUY6dL0Iuz8DZFxHXbV8hsna_wy_1yAmGHhd5uITHe9e3_nGRAO0VDE8m7GKzY9BMSoCgkC5iAGxwzA6hoYvkhMQQnaI7UAvHQFhSD-2sy0FXJjnScfQkua3xk2BYWgr93BGJy_KFpsJqi9l-nCzzeAQAooY7B0MeCyPwmKGIvQfiRJRgODnIhW8I6h3vuPnfrN6OGKbXQZwvccaYp_E_YsEhZoSo2K48CN6jHnz9B81zBMtl15uZE5vpySyECIE2I2HEDM9knF6imwg24cRkqnmQK2eVc_6c2ezrzAY3x0qFmbFNdCW7wBHeIDwruVCrnm1v9xQrpjBwBCiaBpgCTZOGaBUHWrMKDRhRzyNdfQ92LdUufdBRFKUbht6M9CH04-5xx9FW9_GrsOWMt8G4ZT_QH5fA1rDACK2ckYKvIsWoAe32yj3VcWkW2pXXrrhOVpxODlV1x8D2tgfp05C3jruE_9r3D7V-yKXEAzAu7MaUqT-d1OwiSJY8p0Yy3blKlUsl9jIs916XYsq_j0sDSDzP1T_XMKcK7EKbOqXGxOBx3tyZp-Wt7BJejaAZgHbKydPilu-ZKuG-qPPToYvrOqokwMqEYTh97HHuzxTRTRuMayGMg9oG7CuWBBjtO9zd7c1ZATKdfzy9WkVIE6sT_nIb5DmXXfF2hILfZ-cWROPWkBiKxGFmcwQhTncu22e8eI1RuqUtfHu78S1-idhfNBlE8ChlRlnSZsxoIBsP2jQIlcOKqIkzD48rPLaNlb-4KOrV-g7M0T0c_vDtFNHflsDe0OINgVIZrS_LqSfAUzpqBeNOTaRK4QfHWKe0XAVWZqVls2e3O1kDVScPZzHPYewaGlLCZy8zsQf7at720knJTgK420pKiCmQy7bklhArZorZ0cDAIpx7VQfC7UqgfjvlHZF5qld4CPcDoOX9J186vKLwt6afTOM8CVu1DVh5V5SiHk_OXWY54OHsbzPeGadIXZrxIgxPEMzNoBSSvFN2rIetKA-gc7Dhhb1tdFUQTL2wlC5PqkJ1yXWl3Aga0RBOyv0G5gcbk6yeujOJspC0AZpMm2i_Ry4eZgVAqJcslwbSFBUmWcq6E9LHwN1ayQPPa4ZVlqarGjesQFZAv-FuYRVec4bee_GALF05Nw1FjtKWRh8uD27UXwYPSMvBUQ0MMUXNc0uPytGNj9pDZWW5PTeaVqAR7_x1M5vB35ZaKzc7jJ0SkpSuCL2dt-xeVN8eHEww-6n9ilFQDWvHWfAmpLsFpxDPPN0VQmHrE8m1f8pxf0JT_Agz2eVow1NhVumBSqB5iBjoV--y9wOcZnhbHpa7cUxcSO0v57eg-gMRhTnhkgniQYmCH0FZbq7-LieFLVfWQmch2EidrbKCFXO_OyjoOxtDQpMBwcaVD6byDQZMfnDVWqLfZn4Mk9M8_rGqBJdGmnqWIeau5r2nU4LXVxG9iZR49hCdkq9YDpnW3pYrFUWUHddYT181E5AiSXordKFqz4ViKFClrkSuL50g4NLtv5CvooC9n9uS_kGZm0-iEJdEt767O1Hqlzkp5PpLgPH5tISmqtqSiH52R2ATX68wCCVgZdJigicrrw2V49AAdCYmG-znRQBaH25rb8TA7LR7XUmYc1aR2teuRVl1ISwid5z8ASfuzrYatYAPYy3E45MFiY9CPtLBufUIQIJLauxxZH5yRKqJrUVKpTxm2pCy8ngUhX5EaL4i0XwsQFCyPDk8X71lrRtGHRqio8tbdjb_VrjDh7aZHqkByvrS1YRpLH9OY6PqRxgC0bTOgO3YuX-5y4y_b9erI0V7SpblrsxxEO1xXv_WV2E65kNKEuH_fX3Oh7cfGnTLM4NAg6DzEqP91tIphVMxI8YHyhpQ1j0pFAnIYfddPdw3UOWzvc1aQaaG5JfpsAXRgrEoRXCsQZhejaGyUDHzEH1_hGzrD4Reitp6yQHOWC1pQfOHlwX4l5toIoSx560iNjA1eKyr5Ck97n3szQkSqnD7Zmuq3E_RugcVpztLJb7hz0A6CqjNYnzxMEgFK1TysHJuAViVR0tr8iGM-8492YGIYEThcWaKnKw.RGe5IpIO1i-9ua7NaACJHA
unsigned_challenge=eyJhbGciOiJCUDI1NlIxIiwiZXhwIjoxNjE0MTg2MDkyLCJ0eXAiOiJKV1QiLCJraWQiOiJpZHBTaWcifQ.eyJpc3MiOiJodHRwczovL2lkcC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJzbmMiOiJBSlRELzNkR1VXVGlsaEJwYXp6aGVYcmZUMEE3N21seVlUek94VGVQR2JzPSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJ0b2tlbl90eXBlIjoiY2hhbGxlbmdlIiwibm9uY2UiOiJpMDh2UThXYXRtaGw5REV6emJVTCIsImNsaWVudF9pZCI6ImVSZXplcHRBcHAiLCJzY29wZSI6ImUtcmV6ZXB0IG9wZW5pZCIsInN0YXRlIjoiNUppUnNUaWZWUjdCTXBIaWxzUkYiLCJyZWRpcmVjdF91cmkiOiJodHRwOi8vcmVkaXJlY3QuZ2VtYXRpay5kZS9lcmV6ZXB0IiwiZXhwIjoxNjE0MTg2MDkyLCJpYXQiOjE2MTQxODU5MTIsImNvZGVfY2hhbGxlbmdlIjoiT0QyMDF6Q3lkcmlTNWdQcHVCcVdqSFRMQ2UwUlJha2JzVTF6cjlVNE9lcyIsImp0aSI6IjljOTgyZDEyYzNkN2UyYjcifQ.GunKRHM4vjxaDaIiaw8r4GHxVk8e-PmEAAk-_1CZUIpXRMRZu1w4cD40iZqeOMlN5v4aByMu1KhO91fgF1oz3w

```

### SSO Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1614229112'>"
}
```


### SSO Token (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1614229112'>",
  "kid": "idpSig"
}
{
  "nbf": "<Der Token ist erst ab diesem Zeitpunkt gültig. Beispiel: '1614185912'>",
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1614185912'>",
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
  "exp": "<Gültigkeit des Tokens von 12 Stunden. Beispiel: '1614229112'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1614185912'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>"
}
```


### Unsigned Challenge:

```
{
  "alg": "BP256R1",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1614186092'>",
  "typ": "JWT",
  "kid": "idpSig"
}
{
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'AJTD/3dGUWTilhBpazzheXrfT0A77mlyYTzOxTePGbs='>",
  "code_challenge_method": "S256",
  "token_type": "challenge",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'i08vQ8Watmhl9DEzzbUL'>",
  "client_id": "eRezeptApp",
  "scope": "e-rezept openid",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: '5JiRsTifVR7BMpHilsRF'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "exp": "<Gültigkeit des Tokens von 3 Minuten. Beispiel: '1614186092'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1614185912'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: OD201zCydriS5gPpuBqWjHTLCe0RRakbsU1zr9U4Oes>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '9c982d12c3d7e2b7'>"
}
```


## Authentication Response 

```
302
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Location=https://<FQDN Server>//erezept/token
    ?code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE0MTg5NTEyfQ..IGkYS0Elb4lrxhso.qo_QXlCTjLq4NquAOD9R1j-Fx1YIhABanq3jhGfyCb7CS33Uz3HO4TajYjlwYQGvnpFl5HPh0eVQSr0bg0VfuIXzPM8Om1hfQWKkn4MEisP0kg3I9AixNDAv7nITqeFa59FrhW_YWKQRNXI586pbHtbhiR7zQJ6Nk-Jh3JLqHGClPV80KJ4RoYrHVfb2OVs6WOmdyp51gUjzk5200J2f3PNKBp2PsVZ_F5tefhz7BbWzUkmFGWE7I4CLTbpVZ_SrxfCDbS_zAspRucAOWt9h1J1Ae2O20Nf9uIlUFmkTbWpZX43qc9xLlKDaVikxQlHEAmX228thOCE2JOZzCsk9_-Z7XCeemcWam5KVYPGHDpoORyuZbtOEbWiELLQLA5x_huWrY-7X6iQVFggmTsQsTnkotPdjQRTuCjASNj68wBw-SPJ_G8nd_lxigqGxj_8Oj7kBCkIfCiH7pEjzcuybeSHokJkt1NH1lVppGw3Ij31yUPeS67oKHdFG4QSGyWPsIU38gy1ionr3hfbphVLcIbYZqWhtQNvpv9M6cuFBmvkciby-iW3NHYitft7HLJSiz6l5Qdy_OOjcYw160yhHP_C1hpug4NrwW_VWHuCFETFgoLDIRtCqLyd4N3Ix6mk2hteSttIX3pnqnQRy9Hl2msdosZB36pR4zhdlCt1BF8i6M47CAL5kPbJ65405THtB090iP3YfmF776wAOrRNJyk4ajAGnmSodJDME9JU8XISyLWkarSjv2l5rwoio_Jpjx4157CdqhAx3Pf_GRX1__YNj9IEXoVPJqZORKfRPowMIVui_TfolW1Qpgr8eqBbAoYYzKlU5k9PPWXCwvIdj0rQZTs-Z96RhFZCJ24_pguvejq35yGRmlNMvA-IA0VAgFsaCgs6bQdXuPCqk4iTVmvvsHjPXr5K-53eww7fqKg75c7SUNgrbK5npOsm41yBWHfkGk3mn7kBdbKI9f4zc9RBy8sggKElAZsE_YdQhQz5gM172x3Y5Pzk7EyrCbgtX1Uv7RNem9JjjzW6Ax7ZWCorUibjr1Axvn0vXe3yXPWE6khYNcmushPFFgdnHfXiDsyyNtcvw0p2Ym_h42iiRAQibiQbnO7trxdCrbWztIOHSUy8EYaiod9mKL8RPri_a3riSfzpZeuVGb4Sq9oYYq9DDQaz6h0ThKL1jo-6dWWigxmi8KjToVPT7Vfx54lwCgd33FzS0PWcaVHf5RmUhjfagsCpcNzwnN0Kbn6WCV3zIssmmiRT6Z60LP5qRxO-BAej5tGCkvwE.bO3l2glZoPWm-0RiS3Msyg
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: '5JiRsTifVR7BMpHilsRF'>,
Content-Length=0,
Date=<Zeitpunkt der Antwort. Beispiel 'Wed, 24 Feb 2021 16:58:32 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


### Authorization Code (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 1 Stunden. Beispiel: '1614189512'>"
}
```


### Authorization Code (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "exp": "<Gültigkeit des Tokens von 1 Stunden. Beispiel: '1614189512'>",
  "kid": "idpSig"
}
{
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'JqlaCeXbNMuuTtgsog6V'>",
  "code_challenge_method": "S256",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "token_type": "code",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'i08vQ8Watmhl9DEzzbUL'>",
  "client_id": "eRezeptApp",
  "scope": "e-rezept openid",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1614185912'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: '5JiRsTifVR7BMpHilsRF'>",
  "exp": "<Gültigkeit des Tokens von 1 Stunden. Beispiel: '1614189512'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: OD201zCydriS5gPpuBqWjHTLCe0RRakbsU1zr9U4Oes>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '8c01e81b9c6f71ca'>"
}
```


## Token Request 

```
https://<FQDN Server>/<TOKEN_ENDPOINT>
Multiparts:
client_id=eRezeptApp
code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE0MTg5NTEyfQ..IGkYS0Elb4lrxhso.qo_QXlCTjLq4NquAOD9R1j-Fx1YIhABanq3jhGfyCb7CS33Uz3HO4TajYjlwYQGvnpFl5HPh0eVQSr0bg0VfuIXzPM8Om1hfQWKkn4MEisP0kg3I9AixNDAv7nITqeFa59FrhW_YWKQRNXI586pbHtbhiR7zQJ6Nk-Jh3JLqHGClPV80KJ4RoYrHVfb2OVs6WOmdyp51gUjzk5200J2f3PNKBp2PsVZ_F5tefhz7BbWzUkmFGWE7I4CLTbpVZ_SrxfCDbS_zAspRucAOWt9h1J1Ae2O20Nf9uIlUFmkTbWpZX43qc9xLlKDaVikxQlHEAmX228thOCE2JOZzCsk9_-Z7XCeemcWam5KVYPGHDpoORyuZbtOEbWiELLQLA5x_huWrY-7X6iQVFggmTsQsTnkotPdjQRTuCjASNj68wBw-SPJ_G8nd_lxigqGxj_8Oj7kBCkIfCiH7pEjzcuybeSHokJkt1NH1lVppGw3Ij31yUPeS67oKHdFG4QSGyWPsIU38gy1ionr3hfbphVLcIbYZqWhtQNvpv9M6cuFBmvkciby-iW3NHYitft7HLJSiz6l5Qdy_OOjcYw160yhHP_C1hpug4NrwW_VWHuCFETFgoLDIRtCqLyd4N3Ix6mk2hteSttIX3pnqnQRy9Hl2msdosZB36pR4zhdlCt1BF8i6M47CAL5kPbJ65405THtB090iP3YfmF776wAOrRNJyk4ajAGnmSodJDME9JU8XISyLWkarSjv2l5rwoio_Jpjx4157CdqhAx3Pf_GRX1__YNj9IEXoVPJqZORKfRPowMIVui_TfolW1Qpgr8eqBbAoYYzKlU5k9PPWXCwvIdj0rQZTs-Z96RhFZCJ24_pguvejq35yGRmlNMvA-IA0VAgFsaCgs6bQdXuPCqk4iTVmvvsHjPXr5K-53eww7fqKg75c7SUNgrbK5npOsm41yBWHfkGk3mn7kBdbKI9f4zc9RBy8sggKElAZsE_YdQhQz5gM172x3Y5Pzk7EyrCbgtX1Uv7RNem9JjjzW6Ax7ZWCorUibjr1Axvn0vXe3yXPWE6khYNcmushPFFgdnHfXiDsyyNtcvw0p2Ym_h42iiRAQibiQbnO7trxdCrbWztIOHSUy8EYaiod9mKL8RPri_a3riSfzpZeuVGb4Sq9oYYq9DDQaz6h0ThKL1jo-6dWWigxmi8KjToVPT7Vfx54lwCgd33FzS0PWcaVHf5RmUhjfagsCpcNzwnN0Kbn6WCV3zIssmmiRT6Z60LP5qRxO-BAej5tGCkvwE.bO3l2glZoPWm-0RiS3Msyg
grant_type=authorization_code
key_verifier=eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiRV92djVUUHA3MjBpYldaU2dfT2ppMm9Qa2V3TTYzcnZMVEpGSTdXOXJYayIsInkiOiJFMTk2V3pob0tyYXB1RW94Y1hpYm0wOENIeF83ay0tLUFjTlhKdGNnQS1BIiwiY3J2IjoiQlAtMjU2In19.I80YF2BK0gOIQ-EZezx8Tf6EBWv3NSpAonp6pQ9mqe8c9HQlTNj6-g.iAejdRv6HBkDbyjM.Kesjq6bdD03SfSDMOE3djSOWG5ts8oekXhmLKKHkjkkfrmqT7SA8kkeyP7fdzHbAOj9C0qDgkNx1azgou5K2f_h6pIhl9rOeS-Bm1HNGUWYDeWVQBhUvimqX9OUhYlBFyBohz54C9x7tIRlFmgcgX690pOpko-wSSpU.Ii5Nkr4-X_VBjoea1YD3iA
redirect_uri=http://redirect.gematik.de/erezept

```

### Key verifier (Encryption Header):

```
{
  "alg": "ECDH-ES+A256KW",
  "enc": "A256GCM",
  "epk": {
    "kty": "EC",
    "x": "E_vv5TPp720ibWZSg_Oji2oPkewM63rvLTJFI7W9rXk",
    "y": "E196WzhoKrapuEoxcXibm08CHx_7k---AcNXJtcgA-A",
    "crv": "BP-256"
  }
}
```


Key verifier (Body)


```
{
  "token_key": "d3R4S0xRSVFIR2ZkaHBCdzRQRTJOYVh6TXlUYlM2WkE=",
  "code_verifier": "j5O0owi8MWdqH6RHE6FFsdSjkRvx5TfWVelmT1o_YSg"
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
Date=<Zeitpunkt der Antwort. Beispiel 'Wed, 24 Feb 2021 16:58:32 GMT'>,
Keep-Alive=timeout=60,
Connection=keep-alive
```


Response-Body:

```
{
  "expires_in": 300,
  "token_type": "Bearer",
  "id_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE0MTg2MjEyfQ..MPka_BkMxWgQE8_I.g56jCTWu0r7Iw6LtdpaqaS53HccrZkoKd_Q4eFI5JBhzvYa6tWYl3A3xvgrxSmpwIc5WzLL2jdQO3HL6mJKS0lH0z_3yYSMT0UMVBcymso7qr0aZjKPzR-i_kgzekWy96SZgDE_KlMGeLEzLQx_q7L7Q2fME_eq1w6Osm5XEe2JGRBDFNDbR5mmWpvrJDUZSU8zyooSOofHILMWKzOHqP6ga-BnCpy-yqcL7ttLeNSqddB7L5P7yKKCz7AbMGi0xZGOdoGp1gmWt7KWT3yltdj4Gw625FguAKyqkd-lV78fp85qBAfs9Wnr6PVlCxkRglWPrHlbVZrmCXS8z1HTObmc6rJWY5_7giuMqq6MEuecsA9V-Tc8dIkXnnmCCKevH2Mu6PZ8WSwu-KeQIhZ94D33Y-VsICNMFZh0zcS6C4sl6WoshXix_6Bp1kJ4PMGevCpYPlLc8MN8wJCF1hQ9YqfDHYvmybVLiwYjhSZgU1VwoAORVbg4Mk-H3SPy4noVpbyzzaLY_HETycdxxsOLp-F_BWcw5u9pzejku3U5hF5mWk9DbZmfYmt0G-iCFmAiQ4iay4f5unFbUV9ccVo_5EX6QhLPctRA9voPa_VTD1u2MAleToP-Ih620m-iPTg7AgXQB5rRqmuKqzIoGTDWN_KP93idEtuYeIfbcetAVGp-v5UTSyjPOLzdA8FdBCIrAfJrDOnP6LCHa7F6UTkpe3jusqtB3BC-4EqUcqA3ABpmypTyIfrJighRYI6c6Y9hSAWyw90qn0-GQaW0TVejNZav--h3YrY6spjf-46XViVIFW8ffAopZU3YexFJbyDj82Sj32TNylwQahomEazsXhdlStB27X9q6OfU_HLp0Yw8lMormRtehCepGQKw72wMnkbp8sOQSj42Jzfo0Aaa99sdcPl0ce-qKtaXxLMQYREYqfs_JZc8VRCM_2XE1Z_TW-pq0SZLhyRDm9flTfcPp0lMtcKurYIggB6k34YWwpqzbH2Nfu8MYB06yGhNESf3dLnrcAo8XaeA4NvTVbPa9bMBZRzYREd4GN0Y44-6Rq_tvuSlHwAO1F-1rLBk21DxAKg.8RStkhyA21Pns2GK2aze8g",
  "access_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjE0MTg2MjEyfQ..deLGZGeHjyCjf18B.E40JOV-fzR6zpuIJbGAzNp6yVTsZP3cUTZA6z3xyOSx4npTJFMBRFuR8LM_BuKmuRgZo7oU_GNWjYCqWlNtHJlzL20ujFRTK7GirdPBDAdL84hU_IJ9ckNpbWDEC0kfEqgGkRUVR58v0b9pLrt93CVCREvXQN9JfV3pcw-ASEa9ipCpp1LFNyRyT0VurQivJoI0043rAp1t0qhtB0DD5ZDW6KMIl9TOh_qrumT_btcm-ACJH_3C3Htm1BaKen11ooHchPwyYRJJT3PAwh085JFqELnCthcHB1kCXNZQPuOoBN-qGEANQ84lR5lPMLUdAYf4qqi5CIRKDkdVxmoc_cykBdpJZmOs8h_bss9DSEOM4E2HQE3q7yjVxPm7Mt7C6WccMB19Gn9qrKr_jOUds7cXThoDj4EK08r2BqcjPUl1yRMuG-kWZbjl_eXT7WVsJLaORkIlWUYoQicEDT2u10ilWV6gI5z8tv5Y9ZlIkQvzOmLbVfBf3vRH7kOPyKuXbx03Nc-OtCRbIowGpHbAsU2PYv2PH_8Qyt42DMlarycr9kZVnowu3wuO5kGPStTn7kGYntvobquQETgt-XK_4kwtI4CSXQJ1JcCU_LysryF_oN2VKXxZr38A968rubQsQKDGM-_rs64XzIXZUf_D63mxGyAWoBpuFy9PGmJMZoKWM0SivtLlWPSCMdUDQGMX45Y0MuxaiFnpIB9_PQGil9XInOpUmdlONHK5fVhlqya2UTuakRg0OvvwYqaZmfQqRU0Fav19CA9J89OMANJh7BaF4uGyjG-GRLr6Lo5Is1ZsEmtrmy1_6qG3MAwkxSHRL3rO6pSZ3vVorqSOTW7lwRErpsaN5VnBUXW20czEXt5ynHvt82stgOM84tkmnTahw-ETuRSp3nOeRpt2LVTVErZw2k2PO8nBiBORqKcQbNeXDY5THGsliZNbul8NZxlVKXtaEc7-dufIXCIpgbDoxenvxRTGkrMkzG2Z-0bjZ7itckcs29T8RLNmO3Hr8m2mFH1Xsc-7gWlMXUXVODbYs9hUgK7zVUT5s4gqDUEQ4J6sk4QEgenevu9svAV6rqLkNsN4HVq6XQrSXAOk4vEKulHvN1m1FUv8ej8U4PyN0VhssV8Rd0s1gBScQ.GvXdsImd8CCpcFoQKqCTUA"
}
```


### Access Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1614186212'>"
}
```


### Access Token (Decrypted):

```
{
  "alg": "BP256R1",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1614186212'>",
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
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1614185912'>",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1614186212'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1614185912'>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '54cca192fb917f47'>"
}
```


### ID Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1614186212'>"
}
```


### ID Token (Decrypted):

```
{
  "alg": "BP256R1",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1614186212'>",
  "typ": "JWT",
  "kid": "idpSig"
}
{
  "at_hash": "<Erste 16 Bytes des Hash des Authentication Tokens Base64(subarray(Sha256(authentication_token), 0, 16)). Beispiel: '0fir/efgQ9AOjHOYrKAspg=='>",
  "sub": "<subject. Base64(sha256(audClaim + idNummerClaim + serverSubjectSalt)). Beispiel: 'qDAmiQOl5_rJ5-ok48lbjSs6QH9oya7VuxUJ-_E1HCw'>",
  "professionOID": "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "organizationName": "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "idNummer": "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: 'X114428530'>",
  "amr": "["mfa", "sc", "pin"]",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "given_name": "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Juna'>",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'i08vQ8Watmhl9DEzzbUL'>",
  "aud": "eRezeptApp",
  "acr": "gematik-ehealth-loa-high",
  "azp": "eRezeptApp",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1614185912'>",
  "exp": "<Gültigkeit des Tokens von 5 Minuten. Beispiel: '1614186212'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1614185912'>",
  "family_name": "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: 'Fuchs'>"
}
```


# Discovery Document 
## http://localhost:56270/discoveryDocument 

```
200
Cache-Control=max-age=300,
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Content-Length=2665,
Date=<Zeitpunkt der Antwort. Beispiel 'Wed, 24 Feb 2021 16:58:32 GMT'>,
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
  "alternative_authorization_endpoint": "http://localhost:56270/alt_response",
  "sso_endpoint": "<URL des Authorization Endpunkts.>",
  "pairing_endpoint": "http://localhost:56270/pairing",
  "token_endpoint": "<URL des Authorization Endpunkts.>",
  "uri_disc": "<URL des Discovery-Dokuments>",
  "issuer": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "jwks_uri": "<URL einer JWKS-Struktur mit allen vom Server verwendeten Schlüsseln>",
  "exp": "<Gültigkeit des Tokens von PT24H. Beispiel: '1614272312'>",
  "nbf": "<Der Token ist erst ab diesem Zeitpunkt gültig. Beispiel: '1614185912'>",
  "iat": "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '1614185912'>",
  "uri_puk_idp_enc": "http://localhost:56270/idpEnc/jwks.json",
  "uri_puk_idp_sig": "http://localhost:56270/ipdSig/jwks.json",
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
## http://localhost:56270/jwks 

```
200
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Transfer-Encoding=chunked,
Date=<Zeitpunkt der Antwort. Beispiel 'Wed, 24 Feb 2021 16:58:32 GMT'>,
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
      "kid": "1034953504625805",
      "kty": "EC",
      "crv": "BP-256",
      "x": "AJZQrG1NWxIB3kz/6Z2zojlkJqN3vJXZ3EZnJ6JXTXw5",
      "y": "ZDFZ5XjwWmtgfomv3VOV7qzI5ycUSJysMWDEu3mqRcY\u003d"
    }
  ]
}
```


