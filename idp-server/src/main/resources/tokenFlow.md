# Basic FLOW

Log-In attempt using egk with DN 'CN=Juna Fuchs, GIVENNAME=Juna, SURNAME=Fuchs, OU=X114428530, OU=109500969, O=AOK Plus,
C=DE'

## Authorization Request

```
https://<FQDN Server>/<AUTHORIZATION_ENDPOINT>
    ?client_id=eRezeptApp
    &response_type=code
    &redirect_uri=http://redirect.gematik.de/erezept
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'BZIujYHEfFOovLtHXp5m'>
    &code_challenge=<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: ZENecT-NhaIMxSVMryKwltah7JPatqv7JDZ4q4BUTpk>
    &code_challenge_method=S256
    &scope=e-rezept+openid
    &nonce=<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: '8RqsW7ICuFkZJFPSWZke'>


```

## Authorization Response

```
200
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Transfer-Encoding=chunked,
Date=Mon, 15 Feb 2021 16:58:29 GMT,
Keep-Alive=timeout=60,
Connection=keep-alive
```

Response-Body:

```
{
  "challenge": {
    "rawString": "eyJhbGciOiJCUDI1NlIxIiwidHlwIjoiSldUIiwiZXhwIjoxNjEzNDA4NDg5fQ.eyJpc3MiOiJodHRwczovL2lkcC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwiZXhwIjoxNjEzNDA4NDg5LCJpYXQiOjE2MTM0MDgzMDksInJlc3BvbnNlX3R5cGUiOiJjb2RlIiwic2NvcGUiOiJlLXJlemVwdCBvcGVuaWQiLCJjbGllbnRfaWQiOiJlUmV6ZXB0QXBwIiwic3RhdGUiOiJCWkl1allIRWZGT292THRIWHA1bSIsInJlZGlyZWN0X3VyaSI6Imh0dHA6Ly9yZWRpcmVjdC5nZW1hdGlrLmRlL2VyZXplcHQiLCJjb2RlX2NoYWxsZW5nZV9tZXRob2QiOiJTMjU2IiwiY29kZV9jaGFsbGVuZ2UiOiJaRU5lY1QtTmhhSU14U1ZNcnlLd2x0YWg3SlBhdHF2N0pEWjRxNEJVVHBrIiwidG9rZW5fdHlwZSI6ImNoYWxsZW5nZSIsIm5vbmNlIjoiOFJxc1c3SUN1RmtaSkZQU1daa2UiLCJzbmMiOiIxRTdBMC9EREx3WGd5bmI5dHluSXpTQzJlREo4bDl0UGcvSndXZ2tVb0tnPSIsImp0aSI6IjA2ZDlkZjg2M2M4MGU0NzMifQ.GgaLdEooqBn9Re9XURFY6OFQZ5EDsfBEn7preiCVQ98Oy6fyEFAxiv36AKjfPRrNPt1zJvaLb-M6mrV25mpz4A"
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
  "exp": "<Duration of PT3M. Beispiel: '1613408489'>"
}
{
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "exp": "<Duration of PT3M. Beispiel: '1613408489'>",
  "iat": "<Timestamp of the issueing of the token. Beispiel: '1613408309'>",
  "response_type": "code",
  "scope": "e-rezept openid",
  "client_id": "eRezeptApp",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'BZIujYHEfFOovLtHXp5m'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "code_challenge_method": "S256",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: ZENecT-NhaIMxSVMryKwltah7JPatqv7JDZ4q4BUTpk>",
  "token_type": "challenge",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: '8RqsW7ICuFkZJFPSWZke'>",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: '1E7A0/DDLwXgynb9tynIzSC2eDJ8l9tPg/JwWgkUoKg='>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '06d9df863c80e473'>"
}
```

## Authentication Request

```
https://<FQDN Server>/<AUTHORIZATION_ENDPOINT>

Multiparts:
signed_challenge=eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiTEU1amg4cHRxVm03eGYzbEZYWW5La0gyNnVUQlVLZEZNQVNNcTk3TnctTSIsInkiOiJhRWprWTZtT19fTDhYOFZHTndtWUNWWmFKSUpJRXhoQmV3QWFmTlZFQWJvIiwiY3J2IjoiQlAtMjU2In19.tb9EU657jocxarBG2o_l7pOQq0Ij4uxmFRtkVevXkf5Jev0AdOw1bw.cBK9JmpdxTro_2MT.TrJ19IU3mMUG3K7tmYCZTzRqWplbwj16EJN9-zU3DovTn3I_NNgqdKcbLUlybpGaG7ZdBtdD9kkWH-S2aph-9ET7gfoLw9I6DaTL-Onjc94d71d04eM6J4v79K_ANjH7HEzDcf0pqOCyIk3eu7qnUBJc-pQtYoxhd2ja_jcgltifRJchi0wlSllXpi476VcZrwc_C-hjGHht8xxUDsKwTMl8_-f2OuSMhNYZfP7g72O0Ne4LwgeMhgCDsitxb791gBZnuNa2-dYzG81VSCzzMODAHz8Ska6Rp4JVC6_3uTluWKosOSjEMzCjqGxh77dBuawGgEly5i1wTvcXybfr2hplEsIZWntRnYZMIFrpBXiGKIt-C2hy4t_JTfFjyySTamvhwZkjND73jRTXccLXKmBur3aXYQIV1y7IPTuuN4GRJN4nDGm6w_zQ1lClkG9RYKoS2j6Q4ZKWgrqqsvAVUm4D2ED6dB6hDnk23TagqeF3C2tJxKbFliT6p4zzAzfVAIU54GsaAHs1x3Iks8EXjQ_H2NjhxoFDP_ecrNvsx2a6Ui8Rn7hX7PosK0Z0zVCmVNZ5-VVHChmBTGeCgC2fqmnAgu9SPUIV9cQsEcoItoWqCrk9HcdIJQFP1EkSw-ZwzN1reO1wkU7791tByIOy771r7-_wrwm7lE_sdhMh5F82KUwRa_i8BoFR1T8YWQ-veGYKoZeNccL7vLv-1lARWn1vGgPZryIv3hn5bqY43w8mnB_x5h2Zu8vj3_ao81QkNy7D2kRo_Id7LrN5VbhAiCU24o2H1ENiSH2YPHKHjUNy7vPa8trOjGsJaiZGQTwy0CU_dygutuEFdSGo70JSTJuzssmi6TQ_qCxlWCpLUr3RcidMwrJGz7BMzh1LXccRgSXW7dbdY0xfPbieM19i-IjzCpHN5innXsCpxWWLD6q6UkRB7V30lYMsYAbfZWB4r_jPmIoRp71dLGQsbqA34TRtTsiagIlCKDRyXZCWIwoGAxZNFDvtoRyRkJGD_MZ-Qa3DuU7FDK3-B1zg6CpqAOTwVdKyzC3gavu4Zhy9SMcNIXP-eNXO8Zb9Ot12EacMi35wGFbLnaIbrpQVUSi2pwShMzGocMwHwx1qr5tVAk5lW8zguTCmNN6vO-5zUZaxkA1205SXEx3yF4UFC2_MP9uddpIleLKm-5qYrrmRHyBeMlbcqFGfqbq3OBgnE1IA_USpEzpAFvQ2ZUDhyU4epi4OiVHBaHd-NyvKdiMJv5DCGdj7bPbrU2L2W3yrvzs0LJJ-zOfwdZOhPHCKIUW6bmBf62blnXmxT_gIHijl3ZZ68QrM2x2hWgy-S06cjIZEoSAWxvi3G-K06I8Y3lNXg58-Ekp2zH8TUekm7jv2QbBu7uIqMzMplQr2YOs8bevu_hxq_TbbPuMTh6XAsiYcvrr8pZKeplgHOos8UL4SVgEf07Mg7WN3z1ez3JJVkK5MY0orqfg7jKvSIHOZrhiGLSIRtd3TDcMiFFTN4ZG9yJ0TLj0k3K74xLa0I6i9Ob_iJaB0lTi6JqrRdO59pTQGNP3hNThs2j1KIcmz6t1fsAC2NHHYC-27MYa0A56-wiKMJq1xWm_YpbWB2EmV7_jtqWXdqqXuSZg8ZyIeHVFPPx_L-QqRNxjF9PUF7gjd3jH_xG1-Os7ZFRObh6UnjGv3N8F_tOwKmSkSWcBRvjpzAdMWmbRjfunx19vzvoPaT71xHXq6lqmkgVTJSup3CPll1Lgv7F10MiW68tOyPv2j4_ePAy5giud1M68hozSsAV66MXtSz2LxMViIzBUxHSA0-kSTne7fZ7MSagZU5jCoPDC3ejZI-saAJrG0VLkZ9Rp6d70k2Tx4xlJDi2N44nUnSoXGiVTb9Ft1YOLqc-wKi_1Uq6JZFr4a9ZOZS99pUPrDai0KkPMh3DUld9XNJE8eOHsMTeevt-PhupLaTH8J0tAdFMx8GerMyQjag3MCc-8k_9PINtDK3LvOIMwpa-szs0SVLMgj4qA11c0ZqUO_Vsh6U_inUMR5_1nbGIWSQRTHB0rrVMtDCkL5tC9gUQBxIDpb1XffYqxUK4lI52r3ZFwYQyRus3uHjQrKwhS6htTQb6tqVXgJNA4baaJHlLyJRlUyqbf3960urnDH8lF6K5X6E-LcwMpPONZTgr0rY1-5l6xIGK3nVaSjUev_PoTZXvSJAkP4kTW9krFFtJEln-rBrbORhoylrHKx4BOQSAZ8XuvzAuekpvupVQ45ad_tH7DhPRTAZXEZrXKsfC9wWGlMMbW7AW7uQLtXeIP3NlC9PITMHZCpt4yb-s5kg0E-JL0fRWnLa7a9dgQqzXBIP_UYej3RXvIP95fOD2gf0Yq8ZISN6FOO_d4Iyu4FvuSic-7ooujWyoebHeIYtvL9NfWvc6dnvlfJWn8ahsFerHbypYosChlIDfOpy4bBM7Od5WscKpks3sb1HFgcHDxv8MZwyx9Vg8mLPuoO99qWWhMAL_rThrKcJthZ0EWV8NwPpHMwvknDp5U6zHUXp50F9Z_V51hu-nY5FJeZVJd2cXHiNQHYI80Vr3v7d1Pu8PvJtUNuUdX3Z0cJXGYIenfZOB3G38QbnCNadrvKyv6eXNBo08hdNpz9lzFeLyamcRx2tbUxSsQ_jOarYz4C6rHVpoyGWcqsFu0wb2v6_Vc6Wjt62ymhztX8nxUtM9WMPcN-j_KdmuXPuEV_P71AYD8DNzk0KmrN7nU31RHHjsjILK2-MIjWCTRaDqTGHfx59TQZPzvlLOGxQTVQy-RsXUVCyWX3uPGZsBpunrmDygnlwcZbfoTtNs7DmdlAMvEeEkYVbGoHnbYzg6JK8gLQd691UIryd3_NLt6ykZ15D2O4fSiskHKOzRZdn5y7OWP9Eif0wJu2lOuNMgW232b683BZaRGF23OpkCpPd_Wfh0l17V-w8t3GS7gYbs6VryXOXP3lj-yB2PHAr9I8JAaQgoqeCMb_sfr0_3WvZM-0kwQRCnDox7jCkewXggDnJhEWiKd4QlKCsVETf8uNw6w5y-s4ROO5GClvh5uhPDNht8wT1oBtjp-iTaszfsO8z0AGIa7yhoIy-jtKQvb_9sgUjYMNc8jNythWNbDXpDK1323M1eGTNro47YNu6bKwRLZlJfRpKOTPCK4UWihSx_xDVDu4gX6KpgSPl51yI-BQ9mtayCt-NqJrF8bsJR0PCZ-NTt7gqttkt_y9J1d-Y7Uhv8peKeYDkv0TRsA-3rayGpsmMab59cAdR4fThp29tcXUIER3bSKp7xpVZmy7RWr_D7Qt2HtlCR6p5F9yuAC727vPiphoZygmqMoIwbaamyafW7MigUdba42BzMxgCkedz8Z-ZfxNEcc05kyrvYl5EoVHtrPjaBUiAOiaX43Nwtv-9Af_PoVGaptZk-pfvLnqf2tLsnfCNpR5b04laA.Muk01-_iBLMLDp4Zzvkv9w

```

### Challenge Response (Encryption Header):

```
{
  "alg": "ECDH-ES+A256KW",
  "enc": "A256GCM",
  "epk": {
    "kty": "EC",
    "x": "LE5jh8ptqVm7xf3lFXYnKkH26uTBUKdFMASMq97Nw-M",
    "y": "aEjkY6mO__L8X8VGNwmYCVZaJIJIExhBewAafNVEAbo",
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
  "njwt": "eyJhbGciOiJCUDI1NlIxIiwidHlwIjoiSldUIiwiZXhwIjoxNjEzNDA4NDg5fQ.eyJpc3MiOiJodHRwczovL2lkcC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwiZXhwIjoxNjEzNDA4NDg5LCJpYXQiOjE2MTM0MDgzMDksInJlc3BvbnNlX3R5cGUiOiJjb2RlIiwic2NvcGUiOiJlLXJlemVwdCBvcGVuaWQiLCJjbGllbnRfaWQiOiJlUmV6ZXB0QXBwIiwic3RhdGUiOiJCWkl1allIRWZGT292THRIWHA1bSIsInJlZGlyZWN0X3VyaSI6Imh0dHA6Ly9yZWRpcmVjdC5nZW1hdGlrLmRlL2VyZXplcHQiLCJjb2RlX2NoYWxsZW5nZV9tZXRob2QiOiJTMjU2IiwiY29kZV9jaGFsbGVuZ2UiOiJaRU5lY1QtTmhhSU14U1ZNcnlLd2x0YWg3SlBhdHF2N0pEWjRxNEJVVHBrIiwidG9rZW5fdHlwZSI6ImNoYWxsZW5nZSIsIm5vbmNlIjoiOFJxc1c3SUN1RmtaSkZQU1daa2UiLCJzbmMiOiIxRTdBMC9EREx3WGd5bmI5dHluSXpTQzJlREo4bDl0UGcvSndXZ2tVb0tnPSIsImp0aSI6IjA2ZDlkZjg2M2M4MGU0NzMifQ.GgaLdEooqBn9Re9XURFY6OFQZ5EDsfBEn7preiCVQ98Oy6fyEFAxiv36AKjfPRrNPt1zJvaLb-M6mrV25mpz4A"
}
```

## Authentication Response

```
302
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Location=https://<FQDN Server>/<TOKEN_ENDPOINT>
    ?code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjEzNDA4MzY5fQ..crbSNJLpMXFomdC3.Wnit3hsYzecWsRpJapUsSTDC38Up2Dbox313vhh8BdGMjnS_jHGO4R2wfXjBpuzHL-Fb4U0c6-0RG6F8Qk8P0fn-AYkHmZYpXmacehU7NHH05iBoD1bqAEPLIgTtVOuafDvr09izAq3hBaTsLhNAehFFrS-pKQybRLn9fDiD-lvEXxqbPtWhE-LVsoN-Lr7eYjWCBc1QnhwCdpXAadilNu9Zs6vNC3-slgcPxs-JiMTUE3ZR37OmNTL_MAIc4rCttBUJIarPUEUTxoRJs1Cx9Gv93c7AWeqCE5j6yo6HkkiCkfunaF8JUTop29GDs35mp-uqJOSsfErTUAYL1-LrQbLfvY0lsQXDf0x39rK5b_EuXtrD7nJIsxmoRSmr4Z3R2gmsP2P_u6A6XR3aK29pgJEhsD4p-DnhQrvxUior_7fkDpU1SMeUhu7NhX60pwDX_3Tl4vi0sqHCFzf-_IGiW_LFRVWDxJUlPg25QFqIp4nEQdFT0Xh-fz_TFv9QxgN1-m6j8vCvWZRgGDepQsjLYpCWjSrc_4H9n1E4R0MhaXOa94J26ZVA3fHh_xtsQBGL9d3xzV8YjhKZ5iuswoEjtw4eFAB1mCP9cGdMwZqkjhVa_18BpKWD1-k1BO-7lCfATnlTuU0AEtEpMrCoBrs8y9M-t8aTZxmXvFPYwHSGmqpe-Wx_CvGekiPGnrY3EByDswGLR4b0e08-6exmJLjp3Qg4uh2IQVXPG399h_7oSlzRigUJ2ogHth1lACaPlQZUA50ytbcc293MmhjUiwRV6tD-jcqn2KHM5VONNBYqw1QlhefANtPjdlJxlBhyPzOW-AXOythHYLq1V4uS5HZ8ON-vySGZNU_-G0GKmM4F054OnOr-lQNrpdwrsLE-jWhCYIZzFl1yHIr9pZKH2ET3-c5MGFwazXGzlqqv2S2ByyqtsmjWcdb62ehGVS-bBf0B_DFOAsS9uk1TAB9VxuDCX5FCoCpshitefIU6h2hOyhMP3cZrbxVVjXw3_pNzReeWFavvT1WUNCBkzbh92Crh2zOujp8pEoNVikgFU85Pl3qzHaNcmishfC-l4g0BH_lmD8lXV5TEOEkd15NoC-vKmKvo2xjYjeQeK2SOCAFeT6rm_u-IsfoN-SZWAUpyINACoE4YDntOoHWp1a_C-i-Q3WHtZwnYOu-e4vN0V6Rdhp1kw8sB_qZUq4TMNlcWucLawTzg7E3UrKkR9FaJrndUN25Awzbg0XPP1Xh0oJALAYmA7jA52dIgNeNgfQOy5Po5z7rqEhtHEm7XHBOjk-jrzUYYzuAkS1Y54FkcmEHmJATEf_ILGlO-TNP7fcRC5YLDUn7AMiUw.phmXJSb8hnRrrPq6PkmfxQ
    &sso_token=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjEzNDUxNTA5fQ..S5yDG4wXp38V__v1.MDUx7GKdeGFcJwWZS2QjsyIbBQVqs8TqZStdpHAne7Ar6CtjKNufbTyBe1Fz-1HnVnR3CaA-wKV6jaRlzM0ytQaF4r55SvTTKZgX8TxxOpLnUFcSy8RamAfafWPGpRlUY_CCDWEOMWFVapqNxR33Yj0VHjwlKHwf3KCXsiw59UsqK0oGLdM5fjAb2tcekzhqfYtNIzrHZY0XVKMuKENVekMBe53G8OZCgeEpnoRtocKCrHijvgWpJHY6aB6_hLTe8dg4-ub0DUUdztdaPPZWlpFvLJFW_hDTDN0FJB910RFIOdBqYy_ZJgauPd0y8ZIYcWySiHY2B7YJJw37WiQbuwVeYxrQAjbaLHYZjLqMJjQ0f8BbeE2UriJ8r30C9AmqAu5oQimNZPKZfzkVpNoD1xgJc0TCroV_2bKh0N3wq_1hz6sNtr1nsVFipegen91kU6Y3zx4ymgYw1hlax5RbMNOlgUxPgS8v5KvgEykaUAmErKa94AB7Vr0H0uQCf9q1dOtqkewtPSgcpkxelC4gazgj180aLb3jO2uM7y66YCoS8zD1ylOb81LGE5l-cUOMN6NluRZKaoq68VSvGYW24CEOCDGmknbMfnEIsxYWkFnODfWZ3Q7Ss04iAWiEZn5-QlwgQhweqhs-87ZynNCPH8N9U-Mi6LCFQ1uTlvWz3yTA8J3-6lu-YZa8H5NfjdCHf4CKoil-qLAo7_2KJB4LQdFH5QpIkJ4_etj7X-3BBBETiIFQQa8y0AGZH3CH7bJLOaxlNuHiQ39AL0Y5qWlnEXML9fm4HlegALDQyUM98pkxuDZYIXL-vqtTN3Uj1H3Nk77RrsN8kewaz0M9RsxAwvRJyDfpX-a6b62dYZpsKEkY6HPlCG4ejHJkYhCwKS3A39PVNpM4XfKu7KTruuavMCXlqTUiPAH-GDGItkOMufDHibYLdQPRY9Nb3avZyrOVJ4b-0Kz-bkIh4rtMhSfjpuJKaXlhhve4z7xZkjnB00x4tOVSt1hduFoZ93jaFEyEJWovglMI-dBMKnl6FQycjvo7pHotWoQqUg1gWBevXQ8rC0SqOr1jp-FzXdwLXYflNGJZFn6CL2_fyjC7zNDkiyQjM6rUCL2xF2XOvbFm1YJr5SUBPkulCl1tfD3HGZ3Y5gt62C9TsVjALwImC_YUIok1EtDdZOrAo_nbgzqDuF0MAiWZbiU4BbwglrslwXbLFXvRH1cy_0suxvqQrh8e4Up5jSPJ4Efe-6yGSaSeqK5F3E_Q0DKOjcszqeJ6YUGa9wrLiC_6bAICaoWFw4RC9ioAOm0xn59dLmJb-_6BiHQhLawNp9lgM12UYF5jYj4X6Zw_wUEIqY2CbxnkaHyWcB3XpL96nVCDU7LXY3B6K57iIgk9sIg1gaGYAyLzxB49IlftqSO_j9EfDMkse5zd9pt0i1DQvTqZzNyf09g5UKkBETaV6g0Nn11tkFC6y74NCXOk8_HgfSfAgR4Ydx8GgfhpHDVXPHtCkzIIQsweRi2jD6VXimDvJedqR_7vQlTeXNCfh4c0XjcKdZJQthUIngmRRtQCX-XW0rtXT35d_soShYh4c06cVtdXPwzEgeIFFcjCIb7liAIgmASGo9YxN_T9Gqy1WcTW0GQuEjhSCP3xc7Zh9D82TvAG6xTG08n42hE7p9DSjKQcYUFf5JXXWNHZFWj6y6WU8b-9G6euHLstb5YOWcWXECIG0PZD7yFNqcpb0Jhx_0yT0zIWyhezD0S-Mh_G5KLSaerJ3uk4P-a0vHORmM-lBWg1mTCZV1R0_DQjC0Vaw-31YAEMSFml_DnMUiI3izxL_dLu5SMYrZCDxXmbdqT-GSXAYs7qCpOjq_4-PKkt3RQahB_YLcW-sLyAqLTolL00gSSFUVx6ytbpybKxzL6R5rHJu7cDoeF8_mdjnu7_W_Nt-rv7fxfpUyRlKVBYjfjNCD02oTI7_vhJIYocnzAzojNY39svJsWGa9bbnCNtbvphpty23za5wxcLevUdfUiAdmc3yOZ_SgNjYl0M-I1Vikt6CuSkHQWHjJNM8VBLap-26MqqL0HBV1Oo2x2LeJbn642-noQjutlO8Khxz59Gpf7Pvz0pds0EZ7zKo0xinGIbfcP9QMCCf2hBptOBU6HZEgC15rHJzieSeARJvEyhA64UOWBLoSBpb5tDUmE3F39AFHDiVSYZmpi-I4Am1f_TnCsXIJimtjdpa8HPpQSawRQQFZwYhJLZXsN95bTA7Sf5mU9Z1a8ylbMBSYfxt69HISzFAk0A7qGbkJpfwkY8nFsaKHO7FVbpylklH5gxEBQm-hlkJ05s97tff-ySoRwkVscY-SK3ZXB366yLuoWNoyS4KS2I68qg3yZqZoPmpwCRYpOOGT1-hjA-JuJOm5jTPVfckPO0vjgsfpTj5S2N9xgFuUxP5n87chbmI94_yUA8RmKukJYkFB0hfAApeksPY8zemdXD5fmIWDsD2owIUNLeKaiUXVPQX6OleyNybHx-Kqdws4gmU-zLMBIUbqBZJndAdxj2eXNg-n6yAOkZgPmCS2vT12qeOESlnH8-aSq30aF5EtnTeGAfNykzNwsU93mCjCTS7p_c5tiQidC5WhGos9-JHbbMku3in14W-irk_k84DqczcIAbi1Bc5CqgJXDJ1OLLBjBsftmJsPowYUbwnOiL0pupv39VCFTaMOTXOQ0Lv2b5FdzTq8F82ZvF0y49W2bhH5X8z9GM_tzZISjy9Qtk9XSbsrDf9Bzy_A2q7uMaUhm40R7H_D9sOqv6GfwfOsAcVXeDulkuzrh6R4yN-06JCyCNvG9Hf7luIsm-qyrKUz8qWiBW2gDz.rJMqZXqGCd4C77bZYKM47Q
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'BZIujYHEfFOovLtHXp5m'>,
Content-Length=0,
Date=Mon, 15 Feb 2021 16:58:29 GMT,
Keep-Alive=timeout=60,
Connection=keep-alive
```

### Authorization Code (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Duration of PT1M. Beispiel: '1613408369'>"
}
```

### Authorization Code (Decrypted):

```
{
  "alg": "BP256R1",
  "exp": "<Duration of PT1M. Beispiel: '1613408369'>",
  "typ": "JWT",
  "kid": "authKey"
}
{
  "organizationName": "<professionOID of HBA from given authentication-certificate. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "professionOID": "<professionOID of HBA from given authentication-certificate. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "idNummer": "<KVNR or Telematik-ID from given authentication-certificate. Beispiel: 'X114428530'>",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'UOJmkgxxIpzACDopiUcL'>",
  "code_challenge_method": "S256",
  "given_name": "<'givenName' from given authentication-certificate subject-DN. Beispiel: 'Juna'>",
  "token_type": "code",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: '8RqsW7ICuFkZJFPSWZke'>",
  "client_id": "eRezeptApp",
  "nbf": "<token can not used before this timestamp. Beispiel: '1613408309'>",
  "scope": "e-rezept openid",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1613408309'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'BZIujYHEfFOovLtHXp5m'>",
  "exp": "<Duration of PT1M. Beispiel: '1613408369'>",
  "family_name": "<'surname' from given authentication-certificate subject-DN. Beispiel: 'Fuchs'>",
  "iat": "<Timestamp of the issueing of the token. Beispiel: '1613408309'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: ZENecT-NhaIMxSVMryKwltah7JPatqv7JDZ4q4BUTpk>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '782379886fc60a68'>"
}
```

### SSO Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Duration of PT12H. Beispiel: '1613451509'>"
}
```

### SSO Token (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "exp": "<Duration of PT12H. Beispiel: '1613451509'>",
  "kid": "authKey"
}
{
  "nbf": "<token can not used before this timestamp. Beispiel: '1613408309'>",
  "organizationName": "<professionOID of HBA from given authentication-certificate. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "professionOID": "<professionOID of HBA from given authentication-certificate. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1613408309'>",
  "idNummer": "<KVNR or Telematik-ID from given authentication-certificate. Beispiel: 'X114428530'>",
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
  "given_name": "<'givenName' from given authentication-certificate subject-DN. Beispiel: 'Juna'>",
  "exp": "<Duration of PT12H. Beispiel: '1613451509'>",
  "iat": "<Timestamp of the issueing of the token. Beispiel: '1613408309'>",
  "family_name": "<'surname' from given authentication-certificate subject-DN. Beispiel: 'Fuchs'>"
}
```

## Token Request

```
https://<FQDN Server>/<TOKEN_ENDPOINT>

Multiparts:
client_id=eRezeptApp
code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjEzNDA4MzY5fQ..crbSNJLpMXFomdC3.Wnit3hsYzecWsRpJapUsSTDC38Up2Dbox313vhh8BdGMjnS_jHGO4R2wfXjBpuzHL-Fb4U0c6-0RG6F8Qk8P0fn-AYkHmZYpXmacehU7NHH05iBoD1bqAEPLIgTtVOuafDvr09izAq3hBaTsLhNAehFFrS-pKQybRLn9fDiD-lvEXxqbPtWhE-LVsoN-Lr7eYjWCBc1QnhwCdpXAadilNu9Zs6vNC3-slgcPxs-JiMTUE3ZR37OmNTL_MAIc4rCttBUJIarPUEUTxoRJs1Cx9Gv93c7AWeqCE5j6yo6HkkiCkfunaF8JUTop29GDs35mp-uqJOSsfErTUAYL1-LrQbLfvY0lsQXDf0x39rK5b_EuXtrD7nJIsxmoRSmr4Z3R2gmsP2P_u6A6XR3aK29pgJEhsD4p-DnhQrvxUior_7fkDpU1SMeUhu7NhX60pwDX_3Tl4vi0sqHCFzf-_IGiW_LFRVWDxJUlPg25QFqIp4nEQdFT0Xh-fz_TFv9QxgN1-m6j8vCvWZRgGDepQsjLYpCWjSrc_4H9n1E4R0MhaXOa94J26ZVA3fHh_xtsQBGL9d3xzV8YjhKZ5iuswoEjtw4eFAB1mCP9cGdMwZqkjhVa_18BpKWD1-k1BO-7lCfATnlTuU0AEtEpMrCoBrs8y9M-t8aTZxmXvFPYwHSGmqpe-Wx_CvGekiPGnrY3EByDswGLR4b0e08-6exmJLjp3Qg4uh2IQVXPG399h_7oSlzRigUJ2ogHth1lACaPlQZUA50ytbcc293MmhjUiwRV6tD-jcqn2KHM5VONNBYqw1QlhefANtPjdlJxlBhyPzOW-AXOythHYLq1V4uS5HZ8ON-vySGZNU_-G0GKmM4F054OnOr-lQNrpdwrsLE-jWhCYIZzFl1yHIr9pZKH2ET3-c5MGFwazXGzlqqv2S2ByyqtsmjWcdb62ehGVS-bBf0B_DFOAsS9uk1TAB9VxuDCX5FCoCpshitefIU6h2hOyhMP3cZrbxVVjXw3_pNzReeWFavvT1WUNCBkzbh92Crh2zOujp8pEoNVikgFU85Pl3qzHaNcmishfC-l4g0BH_lmD8lXV5TEOEkd15NoC-vKmKvo2xjYjeQeK2SOCAFeT6rm_u-IsfoN-SZWAUpyINACoE4YDntOoHWp1a_C-i-Q3WHtZwnYOu-e4vN0V6Rdhp1kw8sB_qZUq4TMNlcWucLawTzg7E3UrKkR9FaJrndUN25Awzbg0XPP1Xh0oJALAYmA7jA52dIgNeNgfQOy5Po5z7rqEhtHEm7XHBOjk-jrzUYYzuAkS1Y54FkcmEHmJATEf_ILGlO-TNP7fcRC5YLDUn7AMiUw.phmXJSb8hnRrrPq6PkmfxQ
grant_type=authorization_code
key_verifier=eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiVXViSVdseWptT0R5YUNndXFJbWhnY3RzSVFWaGxFdnd1d1VVNzZrR1BJayIsInkiOiJOTVY3ZXVQaTQ2b3ZyZUMwc1psT2dSUDhsTENLWkNJbF9MRnZUcTF6NEVvIiwiY3J2IjoiQlAtMjU2In19.dHvo9TT9e-3uKkiE8exUsy5j0v2ulLiSei3vlJsPAG6oe0CnABghSQ.8raatFpcwmNEqM6G.8GmGi5zoUdxdae9_sChMDyIp_BqqbUs5kbGmWUCeOu_hrIK9VQp-5vD4zlD6JWNLLzL0TSsVcAuG3N1o_h84qHLKn6tJWslvXaHuewlcmEv3WY96zX35H1qvn3aK_mCnSwRPwjQ8V1FdfHPxKtL3hO_7-Z3hHTevb_s.GxymxuOJYMDw9gIbirxSwg
redirect_uri=http://redirect.gematik.de/erezept

```

### Key verifier (Encryption Header):

```
{
  "alg": "ECDH-ES+A256KW",
  "enc": "A256GCM",
  "epk": {
    "kty": "EC",
    "x": "UubIWlyjmODyaCguqImhgctsIQVhlEvwuwUU76kGPIk",
    "y": "NMV7euPi46ovreC0sZlOgRP8lLCKZCIl_LFvTq1z4Eo",
    "crv": "BP-256"
  }
}
```

Key verifier (Body)

```
{
  "token_key": "TUdiaFV3RlkwdmhJQnBsN1J6Uzd1Vk42SjhXUXJtTUU=",
  "code_verifier": "RHhjt4dICTUI_9iySdEUQTmitKccjo8_P0iCfBjMKLg"
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
Date=Mon, 15 Feb 2021 16:58:29 GMT,
Keep-Alive=timeout=60,
Connection=keep-alive
```

Response-Body:

```
{
  "expires_in": 300,
  "token_type": "Bearer",
  "id_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjEzNDA4NjA5fQ..aXZCxGvYQ3FZWxAl.fFQ8xIMJZtIKpUY8DgsL5Q8IcsrG_2c76izWPBgwf8UliKBEuGGD_IB1I7tnRFohJEtXr1h4X2xSxefrVsUyBsyh0vWW1z21gxiAwyuGH3RPS8NnoCBRtqRVb49i892ZreMoWTwAmljebVBnsiwnS8hAUxXx4bEI9yvpCN5TviztQseijV5yMx04u6yjJ6ZP5DiVdV5HbmTf9CUKmwpD80o5TctRMgI1mWkWGdOG-cZUcof7bmKv_W1Uu_K472KfOyYAXGVDVShk7mGd76EV2goRgPMCEj0SPXVUBu2MjnVcZrNS-RC5ALzkq1CHjduRKqYnfJaZOX3NgcVq0p0qNl5dUL3MZ8B0bAuJwssb0H4nRi0UgMpQzETptgwIsy63Z6NPACQ1ytOJPXniRKB-xUT76Nf8907U69QSgp0Szf4HHoIlBf4BJA05bsj3wZGYKTto3i2LjoR5ItmIAOo8ZZkFMDjPEgwaIsal9dmB0NTSw0RCY2rNQRurtRH1vae8ofJ4umTh506m8ymKq8gyz4xGluxoqJFyfvH-olTJajZfYj-hLL49c7kdJw23X2PAfshSAM3o8BeVXdKTGBJ-IDNbFjFHFQY3gOZbaBzOjw6S0q8w2PJHsbsEx708FFA8rMN7YEW48SVjMg8b4pT99GWmcc9ShO6HxYoN4VcXooiv7BSi559VMrhlz_jTYxJqAyS0nt79vznNhdIZ_LrajOGcVct_ONsWPmIOu5dkw3EkMppPrfB6ebIMHe7CZRrSyB8A0ejy9UgsQok09Ud3T8fuKm101Ztzsj-FY5Xj5A61fJ55eZLDgRW-0pf1LsI-O9ECR65OJl9nTDR5X_NKsvOnSt02UYgLozMwV4E-WJ89lnbyhRXjTG1pVokRsUmhdM-FFowH-5B1GorqymBcE9PSZeWE40drrQIM6cA1drikKbTE0SH6ce9K0UmUfWo163RdH7I-Uxtr11MnNFX3rzqH6gerIa68RGZMs3McvWTyRqVg0LrV53ynH7-JpQFyKDV8UKeP3AzyO-qFt4ALus6YRAqJxWkSxst2DzUMhMbe7Fbdkg.MPXIbMkINFWQzRmsfB_pvw",
  "access_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjEzNDA4NjA5fQ..k9bgBFIU1joIQNsV.jCU2DMvNepqmSYf9eLdhVjYmqi0cakCGMYPOtZIN8S6SPRA2WiqbvKI1-qJt9o-vpELGDuzSzt3OerUSQfT13M7pE_czh66a7ITSnj_oDcJRtNngjLCx5i9WnoFpJ85OcU1rOwHTOMybVe4w9zb2OcsOBUut51U9cH-UpcMdpn0SeKUlOwJE3BLQR5XNKoQjxbaxlkEqwlftTPh1xPUOVWUz85IV1ld-6N1AIH_6Va96xmkjSykXH3e-eigFoe0iQt8R7ZuZqzruQkaADvcXO5bwkG0qgVVHpA6MlC2tTD27jcdBGWz_RDuGm_S_KT8iblthGUFYP3_z4NFyJSabAR-qPzBHthj-ujJ-laKUfvSliQ6EsFmQ26OWvn5THxqD-nFQx_zWV6D9AWuQVrt3v5NSkHcTDD1K8ThyTmic90qoVzvm5mCimn6dZjlHmNPFEiJhxasb64NcWPNLT54fCk0czCkGDENJOClyUq2V6VDSLUC7a3j-KtE1iSdJuW2_K0OBknlZ8ADzPjrmqmLtKfyDOtdIK8ugfD7lQU_DQ0U4IJMDxNa_2usA99OgqKxVW8W-0RqAR2snkqaCu-CoQi5VUOwMArPeB3djClEd2RdaW189_nLTXOA5dli6pqwKXDrTGSLgBawWNoK2dvqJCK8Z4qZd0s5y8d2DQA2zHzTvZmp6xDpGNAmWZvRHvv1jqas7wQ5Og6iyf6CS21PoRiKL4xW1O4LNm42ath8RUQgIjLo6NpyZoOolze97ENCaSZL8l624LtZs0-eEVkYFZ8VzKdGlmMkMPp_chi0wtzHSBEwFBxIEXOwv3Zml--sk_HY9ptY50oklF-gzAmTh2PgHPCvqPG3TdmQ3E6w_0G9WdYJPLgpgV7oTKfaAAspKbL7R-VeV7g6lZhoeoLD2FfgRw_c7zb3TDprxK8cYrpRn46SsigLUkzjz2w8RI5TFJw9pjT0vj-voYAL-zJz_Wz9vzEmZJR9oleYnERkB2aWVut0igrQu5jBs9-QNunw8Zf7K-KimcKU1tDbBVsll6GtcNTqXCukNxQXCvbVBIqNoYUDk5H8kQw2RA4LuvwzDDDQltx0Uk11d-7hM__FNqsGBhZ3ealBDqRzx0DFF.5ckGTIr9xku4-lnuFHZ4sw"
}
```

### Access Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Duration of PT5M. Beispiel: '1613408609'>"
}
```

### Access Token (Decrypted):

```
{
  "alg": "BP256R1",
  "exp": "<Duration of PT5M. Beispiel: '1613408609'>",
  "typ": "at+JWT",
  "kid": "authKey"
}
{
  "sub": "<subject. Base64(sha256(audClaim + idNummerClaim + serverSubjectSalt)). Beispiel: 'qDAmiQOl5_rJ5-ok48lbjSs6QH9oya7VuxUJ-_E1HCw'>",
  "professionOID": "<professionOID of HBA from given authentication-certificate. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "organizationName": "<professionOID of HBA from given authentication-certificate. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "idNummer": "<KVNR or Telematik-ID from given authentication-certificate. Beispiel: 'X114428530'>",
  "amr": "["mfa", "sc", "pin"]",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "given_name": "<'givenName' from given authentication-certificate subject-DN. Beispiel: 'Juna'>",
  "client_id": "eRezeptApp",
  "aud": "https://erp.telematik.de/login",
  "acr": "eidas-loa-high",
  "azp": "eRezeptApp",
  "scope": "e-rezept openid",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1613408309'>",
  "exp": "<Duration of PT5M. Beispiel: '1613408609'>",
  "family_name": "<'surname' from given authentication-certificate subject-DN. Beispiel: 'Fuchs'>",
  "iat": "<Timestamp of the issueing of the token. Beispiel: '1613408309'>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '1e8946a864b19201'>"
}
```

### ID Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Duration of PT5M. Beispiel: '1613408609'>"
}
```

### ID Token (Decrypted):

```
{
  "alg": "BP256R1",
  "exp": "<Duration of PT5M. Beispiel: '1613408609'>",
  "typ": "JWT",
  "kid": "authKey"
}
{
  "at_hash": "<Erste 16 Bytes des Hash des Authentication Tokens Base64(subarray(Sha256(authentication_token), 0, 16)). Beispiel: 'guDkFj06eF4WkTeP88BtFg=='>",
  "sub": "<subject. Base64(sha256(audClaim + idNummerClaim + serverSubjectSalt)). Beispiel: 'qDAmiQOl5_rJ5-ok48lbjSs6QH9oya7VuxUJ-_E1HCw'>",
  "professionOID": "<professionOID of HBA from given authentication-certificate. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "organizationName": "<professionOID of HBA from given authentication-certificate. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "idNummer": "<KVNR or Telematik-ID from given authentication-certificate. Beispiel: 'X114428530'>",
  "amr": "["mfa", "sc", "pin"]",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "given_name": "<'givenName' from given authentication-certificate subject-DN. Beispiel: 'Juna'>",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: '8RqsW7ICuFkZJFPSWZke'>",
  "aud": "eRezeptApp",
  "acr": "eidas-loa-high",
  "azp": "eRezeptApp",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1613408309'>",
  "exp": "<Duration of PT5M. Beispiel: '1613408609'>",
  "iat": "<Timestamp of the issueing of the token. Beispiel: '1613408309'>",
  "family_name": "<'surname' from given authentication-certificate subject-DN. Beispiel: 'Fuchs'>"
}
```

# SSO Flow

## Authorization Request

```
https://<FQDN Server>/<AUTHORIZATION_ENDPOINT>
    ?client_id=eRezeptApp
    &response_type=code
    &redirect_uri=http://redirect.gematik.de/erezept
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'HranHeLxF3yeH5Nl3sNc'>
    &code_challenge=<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: Z14tfFD3krqsyC-eaFf1aqxbPLCQ4sTcbjVYsvSVy74>
    &code_challenge_method=S256
    &scope=e-rezept+openid
    &nonce=<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'yb0mMrEos1wn5A6GfP6L'>


```

## Authorization Response

```
200
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Content-Type=application/json,
Transfer-Encoding=chunked,
Date=Mon, 15 Feb 2021 16:58:29 GMT,
Keep-Alive=timeout=60,
Connection=keep-alive
```

Response-Body:

```
{
  "challenge": {
    "rawString": "eyJhbGciOiJCUDI1NlIxIiwidHlwIjoiSldUIiwiZXhwIjoxNjEzNDA4NDg5fQ.eyJpc3MiOiJodHRwczovL2lkcC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwiZXhwIjoxNjEzNDA4NDg5LCJpYXQiOjE2MTM0MDgzMDksInJlc3BvbnNlX3R5cGUiOiJjb2RlIiwic2NvcGUiOiJlLXJlemVwdCBvcGVuaWQiLCJjbGllbnRfaWQiOiJlUmV6ZXB0QXBwIiwic3RhdGUiOiJIcmFuSGVMeEYzeWVINU5sM3NOYyIsInJlZGlyZWN0X3VyaSI6Imh0dHA6Ly9yZWRpcmVjdC5nZW1hdGlrLmRlL2VyZXplcHQiLCJjb2RlX2NoYWxsZW5nZV9tZXRob2QiOiJTMjU2IiwiY29kZV9jaGFsbGVuZ2UiOiJaMTR0ZkZEM2tycXN5Qy1lYUZmMWFxeGJQTENRNHNUY2JqVllzdlNWeTc0IiwidG9rZW5fdHlwZSI6ImNoYWxsZW5nZSIsIm5vbmNlIjoieWIwbU1yRW9zMXduNUE2R2ZQNkwiLCJzbmMiOiJtR2cwQUsvd2paUW1KOU1seGQydXNMVGVyeUxyS2MwSmhYMXlIYWV0VVZNPSIsImp0aSI6IjU4ZTViNWMwODE0NGI5YzcifQ.CEhdpb4j1yAP74-9109eCRBgNnreE1LgJBJy__zuysEnvC9Tc8LKCLNW3Hpk9gvfRb6yQmwQC_0xE8dXNqBRTQ"
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
  "exp": "<Duration of PT3M. Beispiel: '1613408489'>"
}
{
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "exp": "<Duration of PT3M. Beispiel: '1613408489'>",
  "iat": "<Timestamp of the issueing of the token. Beispiel: '1613408309'>",
  "response_type": "code",
  "scope": "e-rezept openid",
  "client_id": "eRezeptApp",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'HranHeLxF3yeH5Nl3sNc'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "code_challenge_method": "S256",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: Z14tfFD3krqsyC-eaFf1aqxbPLCQ4sTcbjVYsvSVy74>",
  "token_type": "challenge",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'yb0mMrEos1wn5A6GfP6L'>",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'mGg0AK/wjZQmJ9Mlxd2usLTeryLrKc0JhX1yHaetUVM='>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '58e5b5c08144b9c7'>"
}
```

## Authentication Request

```
https://<FQDN Server>/<SSO_ENDPOINT>

Multiparts:
sso_token=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjEzNDUxNTA5fQ..S5yDG4wXp38V__v1.MDUx7GKdeGFcJwWZS2QjsyIbBQVqs8TqZStdpHAne7Ar6CtjKNufbTyBe1Fz-1HnVnR3CaA-wKV6jaRlzM0ytQaF4r55SvTTKZgX8TxxOpLnUFcSy8RamAfafWPGpRlUY_CCDWEOMWFVapqNxR33Yj0VHjwlKHwf3KCXsiw59UsqK0oGLdM5fjAb2tcekzhqfYtNIzrHZY0XVKMuKENVekMBe53G8OZCgeEpnoRtocKCrHijvgWpJHY6aB6_hLTe8dg4-ub0DUUdztdaPPZWlpFvLJFW_hDTDN0FJB910RFIOdBqYy_ZJgauPd0y8ZIYcWySiHY2B7YJJw37WiQbuwVeYxrQAjbaLHYZjLqMJjQ0f8BbeE2UriJ8r30C9AmqAu5oQimNZPKZfzkVpNoD1xgJc0TCroV_2bKh0N3wq_1hz6sNtr1nsVFipegen91kU6Y3zx4ymgYw1hlax5RbMNOlgUxPgS8v5KvgEykaUAmErKa94AB7Vr0H0uQCf9q1dOtqkewtPSgcpkxelC4gazgj180aLb3jO2uM7y66YCoS8zD1ylOb81LGE5l-cUOMN6NluRZKaoq68VSvGYW24CEOCDGmknbMfnEIsxYWkFnODfWZ3Q7Ss04iAWiEZn5-QlwgQhweqhs-87ZynNCPH8N9U-Mi6LCFQ1uTlvWz3yTA8J3-6lu-YZa8H5NfjdCHf4CKoil-qLAo7_2KJB4LQdFH5QpIkJ4_etj7X-3BBBETiIFQQa8y0AGZH3CH7bJLOaxlNuHiQ39AL0Y5qWlnEXML9fm4HlegALDQyUM98pkxuDZYIXL-vqtTN3Uj1H3Nk77RrsN8kewaz0M9RsxAwvRJyDfpX-a6b62dYZpsKEkY6HPlCG4ejHJkYhCwKS3A39PVNpM4XfKu7KTruuavMCXlqTUiPAH-GDGItkOMufDHibYLdQPRY9Nb3avZyrOVJ4b-0Kz-bkIh4rtMhSfjpuJKaXlhhve4z7xZkjnB00x4tOVSt1hduFoZ93jaFEyEJWovglMI-dBMKnl6FQycjvo7pHotWoQqUg1gWBevXQ8rC0SqOr1jp-FzXdwLXYflNGJZFn6CL2_fyjC7zNDkiyQjM6rUCL2xF2XOvbFm1YJr5SUBPkulCl1tfD3HGZ3Y5gt62C9TsVjALwImC_YUIok1EtDdZOrAo_nbgzqDuF0MAiWZbiU4BbwglrslwXbLFXvRH1cy_0suxvqQrh8e4Up5jSPJ4Efe-6yGSaSeqK5F3E_Q0DKOjcszqeJ6YUGa9wrLiC_6bAICaoWFw4RC9ioAOm0xn59dLmJb-_6BiHQhLawNp9lgM12UYF5jYj4X6Zw_wUEIqY2CbxnkaHyWcB3XpL96nVCDU7LXY3B6K57iIgk9sIg1gaGYAyLzxB49IlftqSO_j9EfDMkse5zd9pt0i1DQvTqZzNyf09g5UKkBETaV6g0Nn11tkFC6y74NCXOk8_HgfSfAgR4Ydx8GgfhpHDVXPHtCkzIIQsweRi2jD6VXimDvJedqR_7vQlTeXNCfh4c0XjcKdZJQthUIngmRRtQCX-XW0rtXT35d_soShYh4c06cVtdXPwzEgeIFFcjCIb7liAIgmASGo9YxN_T9Gqy1WcTW0GQuEjhSCP3xc7Zh9D82TvAG6xTG08n42hE7p9DSjKQcYUFf5JXXWNHZFWj6y6WU8b-9G6euHLstb5YOWcWXECIG0PZD7yFNqcpb0Jhx_0yT0zIWyhezD0S-Mh_G5KLSaerJ3uk4P-a0vHORmM-lBWg1mTCZV1R0_DQjC0Vaw-31YAEMSFml_DnMUiI3izxL_dLu5SMYrZCDxXmbdqT-GSXAYs7qCpOjq_4-PKkt3RQahB_YLcW-sLyAqLTolL00gSSFUVx6ytbpybKxzL6R5rHJu7cDoeF8_mdjnu7_W_Nt-rv7fxfpUyRlKVBYjfjNCD02oTI7_vhJIYocnzAzojNY39svJsWGa9bbnCNtbvphpty23za5wxcLevUdfUiAdmc3yOZ_SgNjYl0M-I1Vikt6CuSkHQWHjJNM8VBLap-26MqqL0HBV1Oo2x2LeJbn642-noQjutlO8Khxz59Gpf7Pvz0pds0EZ7zKo0xinGIbfcP9QMCCf2hBptOBU6HZEgC15rHJzieSeARJvEyhA64UOWBLoSBpb5tDUmE3F39AFHDiVSYZmpi-I4Am1f_TnCsXIJimtjdpa8HPpQSawRQQFZwYhJLZXsN95bTA7Sf5mU9Z1a8ylbMBSYfxt69HISzFAk0A7qGbkJpfwkY8nFsaKHO7FVbpylklH5gxEBQm-hlkJ05s97tff-ySoRwkVscY-SK3ZXB366yLuoWNoyS4KS2I68qg3yZqZoPmpwCRYpOOGT1-hjA-JuJOm5jTPVfckPO0vjgsfpTj5S2N9xgFuUxP5n87chbmI94_yUA8RmKukJYkFB0hfAApeksPY8zemdXD5fmIWDsD2owIUNLeKaiUXVPQX6OleyNybHx-Kqdws4gmU-zLMBIUbqBZJndAdxj2eXNg-n6yAOkZgPmCS2vT12qeOESlnH8-aSq30aF5EtnTeGAfNykzNwsU93mCjCTS7p_c5tiQidC5WhGos9-JHbbMku3in14W-irk_k84DqczcIAbi1Bc5CqgJXDJ1OLLBjBsftmJsPowYUbwnOiL0pupv39VCFTaMOTXOQ0Lv2b5FdzTq8F82ZvF0y49W2bhH5X8z9GM_tzZISjy9Qtk9XSbsrDf9Bzy_A2q7uMaUhm40R7H_D9sOqv6GfwfOsAcVXeDulkuzrh6R4yN-06JCyCNvG9Hf7luIsm-qyrKUz8qWiBW2gDz.rJMqZXqGCd4C77bZYKM47Q
unsigned_challenge=eyJhbGciOiJCUDI1NlIxIiwidHlwIjoiSldUIiwiZXhwIjoxNjEzNDA4NDg5fQ.eyJpc3MiOiJodHRwczovL2lkcC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwiZXhwIjoxNjEzNDA4NDg5LCJpYXQiOjE2MTM0MDgzMDksInJlc3BvbnNlX3R5cGUiOiJjb2RlIiwic2NvcGUiOiJlLXJlemVwdCBvcGVuaWQiLCJjbGllbnRfaWQiOiJlUmV6ZXB0QXBwIiwic3RhdGUiOiJIcmFuSGVMeEYzeWVINU5sM3NOYyIsInJlZGlyZWN0X3VyaSI6Imh0dHA6Ly9yZWRpcmVjdC5nZW1hdGlrLmRlL2VyZXplcHQiLCJjb2RlX2NoYWxsZW5nZV9tZXRob2QiOiJTMjU2IiwiY29kZV9jaGFsbGVuZ2UiOiJaMTR0ZkZEM2tycXN5Qy1lYUZmMWFxeGJQTENRNHNUY2JqVllzdlNWeTc0IiwidG9rZW5fdHlwZSI6ImNoYWxsZW5nZSIsIm5vbmNlIjoieWIwbU1yRW9zMXduNUE2R2ZQNkwiLCJzbmMiOiJtR2cwQUsvd2paUW1KOU1seGQydXNMVGVyeUxyS2MwSmhYMXlIYWV0VVZNPSIsImp0aSI6IjU4ZTViNWMwODE0NGI5YzcifQ.CEhdpb4j1yAP74-9109eCRBgNnreE1LgJBJy__zuysEnvC9Tc8LKCLNW3Hpk9gvfRb6yQmwQC_0xE8dXNqBRTQ

```

### SSO Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Duration of PT12H. Beispiel: '1613451509'>"
}
```

### SSO Token (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "exp": "<Duration of PT12H. Beispiel: '1613451509'>",
  "kid": "authKey"
}
{
  "nbf": "<token can not used before this timestamp. Beispiel: '1613408309'>",
  "organizationName": "<professionOID of HBA from given authentication-certificate. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "professionOID": "<professionOID of HBA from given authentication-certificate. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1613408309'>",
  "idNummer": "<KVNR or Telematik-ID from given authentication-certificate. Beispiel: 'X114428530'>",
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
  "given_name": "<'givenName' from given authentication-certificate subject-DN. Beispiel: 'Juna'>",
  "exp": "<Duration of PT12H. Beispiel: '1613451509'>",
  "iat": "<Timestamp of the issueing of the token. Beispiel: '1613408309'>",
  "family_name": "<'surname' from given authentication-certificate subject-DN. Beispiel: 'Fuchs'>"
}
```

### Unsigned Challenge:

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "exp": "<Duration of PT3M. Beispiel: '1613408489'>"
}
{
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "exp": "<Duration of PT3M. Beispiel: '1613408489'>",
  "iat": "<Timestamp of the issueing of the token. Beispiel: '1613408309'>",
  "response_type": "code",
  "scope": "e-rezept openid",
  "client_id": "eRezeptApp",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'HranHeLxF3yeH5Nl3sNc'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "code_challenge_method": "S256",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: Z14tfFD3krqsyC-eaFf1aqxbPLCQ4sTcbjVYsvSVy74>",
  "token_type": "challenge",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'yb0mMrEos1wn5A6GfP6L'>",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'mGg0AK/wjZQmJ9Mlxd2usLTeryLrKc0JhX1yHaetUVM='>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '58e5b5c08144b9c7'>"
}
```

## Authentication Response

```
302
Cache-Control=no-store,
Pragma=no-cache,
Version=0.1-SNAPSHOT,
Location=https://<FQDN Server>/<TOKEN_ENDPOINT>
    ?code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjEzNDExOTA5fQ..6YgI4Eotckq2vE4Q.Z9yNC4beYeO3a_PHI4IvcnluW5HeyFE9iI2-qDzyXLzWA16T1VuvIN3NqfGAV3zIYv31M50ANhe8dPFif6xWmUsF3MnTNb8JMb6fgyiv2LORZQn7m047nprZ6v__1Bkv_rh1hG5qC-qMKn58UJbdFqq6eFEOXBk--dljm9fGc2pltxaRfC_xslfSvIyWLDcYk1dHerL9bIUZKNEAt0cwvb3PeaXriExjReJhn58uZMz82ng1yn26MRyORp8wQ2GKj-Mu3Qoi6HNecxxcL1dGxPzdp-07wRDWLooF5g7FUMeziAVxIKMyJF8TFUQgUQWuVt8cKp_53pQM4hJ8JtMggZy-D-wD5Jbn5CbOq6X_qF7v0ndqjWExa1j_5smHYckRCseqw5P1pjg18jRtoukW0UXy2dwDkfWPXIDoxXYAg9VB1F5N6kQCICn24BY3ruEwMR13_DZDjlTNre2UR6KQAQucSUlFflN83-LBH5JIL4ZPKPWp8EKIXp2rPwMSvjKtDH9sAcCCF9t5xWA5aRAGw-iziP_xlfsgEKJNH9yL_rzqX2idGAyC8R1Q5enPG4wSepuj5HtSNfGtXGFyEAmjptHPW7NLkoP8sYrxiRoRuugQZMq7d5EvE6JbRXioKKwN-Lm1nfDNvkuveATQx8ksELXGlmb1URCwIXvRrcXXlJC8ioHE-YJ_vpAqhzbf5k7WIGi13JeTaqpVSNB51lh3EyGBNJr5sHfDN-FIiOM-nody7cauVBA-32wqTgpvi8PnpuhULuMnO4EP6ZRRUSKWkHDcsbOdCGKxa7WTMfiO0-Vru4nJfAvf5yjopYHgKgUHX0anGDwUn7PVgAKCmdM3cuWYyC1xnazG7Gwn5C7lH-PXpSWMyEPwg6ZzRcxBsXDScscy_8EzIKb-VcXUG4A5ndJ98jZx20Uf6n1tQmXxE5rSWih3OzN81wAAstYqMYgD9kvVEwn5yxa6VGDFaInG0J_Tll3Lx5VM994Tfk04ckOMVSxGqJpzNliTg5gc3J5nVN3HRRg7Tbe1vLQA4Nv3VHrDxt8tVOiufkOu6Q9bl4vj4s1iB_UNc4PeDT58qDrDUM4uSgnV-j-lWShSBxiJsJHI1OzZRibbBrRPRDE7WClWjDYlS1Ltvcm1Tg3ByWeksWK_J85wm8RLbIcIqA9vFABIKaB3Sm8mh_N8cBcdbM5priCvrZuPmStVnTEGttvtwoWPPUci9jK_dHASnm2a5uaSCzxz5XkzCE1tymNX_dC_Je8zYjJ8wl2_f4Ep40MZh5Ir4cXAuELJ.RcXhHWrYAaPrH9hNw7vGXA
    &state=<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'HranHeLxF3yeH5Nl3sNc'>,
Content-Length=0,
Date=Mon, 15 Feb 2021 16:58:29 GMT,
Keep-Alive=timeout=60,
Connection=keep-alive
```

### Authorization Code (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Duration of PT1H. Beispiel: '1613411909'>"
}
```

### Authorization Code (Decrypted):

```
{
  "alg": "BP256R1",
  "typ": "JWT",
  "exp": "<Duration of PT1H. Beispiel: '1613411909'>",
  "kid": "authKey"
}
{
  "organizationName": "<professionOID of HBA from given authentication-certificate. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "professionOID": "<professionOID of HBA from given authentication-certificate. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "idNummer": "<KVNR or Telematik-ID from given authentication-certificate. Beispiel: 'X114428530'>",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "response_type": "code",
  "snc": "<server-nonce. Used to introduce noise. Beispiel: 'wUFBw4v9jy0czcKP0BGF'>",
  "code_challenge_method": "S256",
  "given_name": "<'givenName' from given authentication-certificate subject-DN. Beispiel: 'Juna'>",
  "token_type": "code",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'yb0mMrEos1wn5A6GfP6L'>",
  "client_id": "eRezeptApp",
  "scope": "e-rezept openid",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1613408309'>",
  "redirect_uri": "http://redirect.gematik.de/erezept",
  "state": "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: 'HranHeLxF3yeH5Nl3sNc'>",
  "exp": "<Duration of PT1H. Beispiel: '1613411909'>",
  "family_name": "<'surname' from given authentication-certificate subject-DN. Beispiel: 'Fuchs'>",
  "code_challenge": "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: Z14tfFD3krqsyC-eaFf1aqxbPLCQ4sTcbjVYsvSVy74>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '0e44a4c9940c04bb'>"
}
```

## Token Request

```
https://<FQDN Server>/<TOKEN_ENDPOINT>

Multiparts:
client_id=eRezeptApp
code=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjEzNDExOTA5fQ..6YgI4Eotckq2vE4Q.Z9yNC4beYeO3a_PHI4IvcnluW5HeyFE9iI2-qDzyXLzWA16T1VuvIN3NqfGAV3zIYv31M50ANhe8dPFif6xWmUsF3MnTNb8JMb6fgyiv2LORZQn7m047nprZ6v__1Bkv_rh1hG5qC-qMKn58UJbdFqq6eFEOXBk--dljm9fGc2pltxaRfC_xslfSvIyWLDcYk1dHerL9bIUZKNEAt0cwvb3PeaXriExjReJhn58uZMz82ng1yn26MRyORp8wQ2GKj-Mu3Qoi6HNecxxcL1dGxPzdp-07wRDWLooF5g7FUMeziAVxIKMyJF8TFUQgUQWuVt8cKp_53pQM4hJ8JtMggZy-D-wD5Jbn5CbOq6X_qF7v0ndqjWExa1j_5smHYckRCseqw5P1pjg18jRtoukW0UXy2dwDkfWPXIDoxXYAg9VB1F5N6kQCICn24BY3ruEwMR13_DZDjlTNre2UR6KQAQucSUlFflN83-LBH5JIL4ZPKPWp8EKIXp2rPwMSvjKtDH9sAcCCF9t5xWA5aRAGw-iziP_xlfsgEKJNH9yL_rzqX2idGAyC8R1Q5enPG4wSepuj5HtSNfGtXGFyEAmjptHPW7NLkoP8sYrxiRoRuugQZMq7d5EvE6JbRXioKKwN-Lm1nfDNvkuveATQx8ksELXGlmb1URCwIXvRrcXXlJC8ioHE-YJ_vpAqhzbf5k7WIGi13JeTaqpVSNB51lh3EyGBNJr5sHfDN-FIiOM-nody7cauVBA-32wqTgpvi8PnpuhULuMnO4EP6ZRRUSKWkHDcsbOdCGKxa7WTMfiO0-Vru4nJfAvf5yjopYHgKgUHX0anGDwUn7PVgAKCmdM3cuWYyC1xnazG7Gwn5C7lH-PXpSWMyEPwg6ZzRcxBsXDScscy_8EzIKb-VcXUG4A5ndJ98jZx20Uf6n1tQmXxE5rSWih3OzN81wAAstYqMYgD9kvVEwn5yxa6VGDFaInG0J_Tll3Lx5VM994Tfk04ckOMVSxGqJpzNliTg5gc3J5nVN3HRRg7Tbe1vLQA4Nv3VHrDxt8tVOiufkOu6Q9bl4vj4s1iB_UNc4PeDT58qDrDUM4uSgnV-j-lWShSBxiJsJHI1OzZRibbBrRPRDE7WClWjDYlS1Ltvcm1Tg3ByWeksWK_J85wm8RLbIcIqA9vFABIKaB3Sm8mh_N8cBcdbM5priCvrZuPmStVnTEGttvtwoWPPUci9jK_dHASnm2a5uaSCzxz5XkzCE1tymNX_dC_Je8zYjJ8wl2_f4Ep40MZh5Ir4cXAuELJ.RcXhHWrYAaPrH9hNw7vGXA
grant_type=authorization_code
key_verifier=eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoibDluYm40VTgybzY1RFA5Y185TlVvZ1VoWmJiMTFzRjAzcFpMaWRKSU9NMCIsInkiOiJCS053akc4eE9fcmlLeWVJX0Q1RnkyNFhYUlFRMEFKYjBEVnB0UWRSTnNnIiwiY3J2IjoiQlAtMjU2In19.buPkAdurfObrn7Y0o0ZjK13dQPHXRFW4UTt3evh3SrrtWh9rhgwYBA.JYtLfYfJdAQG_kUB.IbtuQIwHCv6fPkfq8Nce_6z2APLD91Z8S4nrTbWe5PtiTY6kn3HyhsowLuoA1_0lMpU55IckTTBrns8MxS0iDnN4gP0K5Wh6th96DvR0ynN8yqnv4jqX-Nb5ZgSz77dpKFqY8iyY8MnvDQq3MjBmmFNf2BFBAH2-E_4.ZQ3Vd5EeIP92IKGaaF_z_A
redirect_uri=http://redirect.gematik.de/erezept

```

### Key verifier (Encryption Header):

```
{
  "alg": "ECDH-ES+A256KW",
  "enc": "A256GCM",
  "epk": {
    "kty": "EC",
    "x": "l9nbn4U82o65DP9c_9NUogUhZbb11sF03pZLidJIOM0",
    "y": "BKNwjG8xO_riKyeI_D5Fy24XXRQQ0AJb0DVptQdRNsg",
    "crv": "BP-256"
  }
}
```

Key verifier (Body)

```
{
  "token_key": "RDhMU1MyZEhIU0xLWEUxUUlPMkFHMzBQbzN4V3k3TWw=",
  "code_verifier": "KknMOThTedG_MdTe3IQ1dM8sq7_fAWfJpZlz4aPYaM8"
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
Date=Mon, 15 Feb 2021 16:58:29 GMT,
Keep-Alive=timeout=60,
Connection=keep-alive
```

Response-Body:

```
{
  "expires_in": 300,
  "token_type": "Bearer",
  "id_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjEzNDA4NjA5fQ..C2D6X-7N1PAQ2JM0.mAO9W6kfFwHIo8lFQtfmd1tEjl3AEjrHjq-dss_6_Wbkmml_rrWj6E0sh4AfvlNrkPK3GP5cyzU71c-HBYyllFZE01TQcq8Pghe8u6Y7SPCgf5LcWzb1JUrfXG8J2BDbiLrvj013Ec2geaUTda3FVradpY3QkkEKU9v0jFEU4ERUbPZMO6KCFAXbZNounxpUzx7yZvoZlXrSQEtqfawsC7B985oKU5o8TN2Ju7eFPiHy0ICyfUjhmk-TfnahcfMmSAVrKeqU5pF1Bo_fZsl_QnaYho0XigdkfrqiQknFNk124nAhJgOllftR2eAp30rkBrW-x-DnvgPLH1vTokB1TTDu0pt2U4BjCiR9FZocpxa2paRkHLH2oXfZeVqGM2jvlaRprYUU6YBrZSu_QxRaUOMdBSXl-5QQ_JDbPCbHuI6iNkA-0KqGoCP959ciEsNoMdC0HcULgtkjRESYPHVqsp6AqF-l6PsiRwHJ2t4LifUVxPw-RnMhBtrTfEjXHAt5ObIBPNYyN0aNg-tH_LTlEBRgcwALsX1QDeRJHVCnau42N-HpauOAE8Gzb_XPszQLj49CNX6HA-fzDddLfW5UtDRC3x7tmHwKYheZ9Z0JDTwPsi43ZjVhNbjDaIjMOmwJDEtFyBc-XKcnWvGf4EiVouJKL5Df3hinZXYu3pdDw9Hd5gNf4kHwy4OUPf3A4ecoP3gVp7w3RDAcXNja0ureLNeEWXzdslDbEu4A6GH3ke_ldM8fOXllWHAADKIRbVpTd-6Q_KwTgHjk2tI0M-EIOEZn_jPa2bWt5Dc48WdShKUJ3fr68TQDvQmmNdImq1IBrzmicvEfzEDmxYLsarJqmeqfFSBdNmCyL0CM-toblsOkdOjnSK1WPsk3LlrUev6lJdDqpuX0pvJr_s00Qlz0FAoFjx_aw8tOf2cxItFTm1Sp4Ipm5VMuO8Al-EgqFnuRyohVDLObsfIRrd7z5RoF0R5P-vYux5odTbne6GvfLXQFXQf-p5nR65OAWbt_e5selH7kD1oeVDaDZFw7Y6gFbveqKxm8Yj4EJ7biir2Alh3EPTd7aA.MQ9NTVNvW-J8CPBKj380ew",
  "access_token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiZXhwIjoxNjEzNDA4NjA5fQ..6NCDirPP6IrbfWcG.GBbFsd72PlaIJgpLMc-6yPDF9ketS3duA7zhbTiManKRQj4qt-8gaSLu8vxUjUm5ZpLYTVtFsUirVaT6Jg3O3T8S859_-9H__jdK0GT8mwZLtjniHYUDMsBl2csQOtYpjVyZXETLrcxOh_B05ahE2axGPPPJbEEmJSvguIkQIoHVRck0jrkZe8jTxFfhnTlg5hUGUSj_yUV4DpGy-WkKXfCGbGVpCXce3uvJlrZqRArY29bd8nn3SMjQzChlUnYRVBP18sHFqS5TdJmRDQVz8FntU8I_WxCeg2qniTOy-u-wPpaI38NSxK1W0qPgvtf0IDPq_RiFlBifALc_WYsVojPSyf27CMr7Rbaac2Oja-2nTnVUFPDs7_TfMP5NOQ1WNwCjQfsjMLZQBB4P_NAlE9WzeW1d7HpDACI6dhc2MbpakQmvl3wAuulLCJXK6ZZEDgG0F6gxysy2627Dy4cyx8YuEde77iHZ2Y38Xyq-b-Q2yxwqCF_NjEhhzcyr1KN_TJF7oD0vEkrrXNRX0QTSuOXO7N5WATu5lzxuuRvhINPX34OFZ3mdgvwFVjLmodi6KwRF0AD5BaX5pK6RLivaovE9vqNw5bYmWbLid0-vg-CJJOdSU4zJ0AKF0jG2uAcBYxbHS7YFRR8mr_txFXTf6x_ZCb6pktCjqwURjOhf8-9W08LI9M_IN6z2ct6XT1JQSycc2Q-ZXLLXV8tvoLKxI7Vlss77dw3cYoXF5KYfzvGrl_c2tTQ4zcYP90MwRHh3ey2GpOl6fkwxOpaN_VujcMdwEuIzti7pX7iJ6-76doGDn8-QgJ69ugAOfQvGvNugCgGlD8f69kOYajg1rER2NIFfOxaxMe7qEtPIntrL7iLEkby2IW6xiecSOzk3HREyKIKWRVHAQmxykTnlRPVygrpy_EFOMLTqDMM5-9I2PBmvE1iydx9QRrE-TBm8vCTLOcG2UqCrB7Z3njp7hWI7JbxOnrKZ02K4kSlm86AmKDV-HTaNSG5_SFLlPp_pDStF9-2LsGVJIBXHjgZgMumgIly0FUXcAVNHZz85WzAXO1YowsdSsZIaMy1vDW4EDJ7Xn54xcxzeBg3mIxNZQfUn4jzKbFPKbEo0CtSAPIY-.OQCGwqpplZyMEUm3ySM6iw"
}
```

### Access Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Duration of PT5M. Beispiel: '1613408609'>"
}
```

### Access Token (Decrypted):

```
{
  "alg": "BP256R1",
  "exp": "<Duration of PT5M. Beispiel: '1613408609'>",
  "typ": "at+JWT",
  "kid": "authKey"
}
{
  "sub": "<subject. Base64(sha256(audClaim + idNummerClaim + serverSubjectSalt)). Beispiel: 'qDAmiQOl5_rJ5-ok48lbjSs6QH9oya7VuxUJ-_E1HCw'>",
  "professionOID": "<professionOID of HBA from given authentication-certificate. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "organizationName": "<professionOID of HBA from given authentication-certificate. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "idNummer": "<KVNR or Telematik-ID from given authentication-certificate. Beispiel: 'X114428530'>",
  "amr": "["mfa", "sc", "pin"]",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "given_name": "<'givenName' from given authentication-certificate subject-DN. Beispiel: 'Juna'>",
  "client_id": "eRezeptApp",
  "aud": "https://erp.telematik.de/login",
  "acr": "eidas-loa-high",
  "azp": "eRezeptApp",
  "scope": "e-rezept openid",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1613408309'>",
  "exp": "<Duration of PT5M. Beispiel: '1613408609'>",
  "family_name": "<'surname' from given authentication-certificate subject-DN. Beispiel: 'Fuchs'>",
  "iat": "<Timestamp of the issueing of the token. Beispiel: '1613408309'>",
  "jti": "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '4ce26b4e5a38e319'>"
}
```

### ID Token (Encryption Header):

```
{
  "alg": "dir",
  "enc": "A256GCM",
  "exp": "<Duration of PT5M. Beispiel: '1613408609'>"
}
```

### ID Token (Decrypted):

```
{
  "alg": "BP256R1",
  "exp": "<Duration of PT5M. Beispiel: '1613408609'>",
  "typ": "JWT",
  "kid": "authKey"
}
{
  "at_hash": "<Erste 16 Bytes des Hash des Authentication Tokens Base64(subarray(Sha256(authentication_token), 0, 16)). Beispiel: 'igxKRbtgjkpktVY/aySyrQ=='>",
  "sub": "<subject. Base64(sha256(audClaim + idNummerClaim + serverSubjectSalt)). Beispiel: 'qDAmiQOl5_rJ5-ok48lbjSs6QH9oya7VuxUJ-_E1HCw'>",
  "professionOID": "<professionOID of HBA from given authentication-certificate. Null if not present. Beispiel: '1.2.276.0.76.4.49'>",
  "organizationName": "<professionOID of HBA from given authentication-certificate. Null if not present. Beispiel: 'gematik GmbH NOT-VALID'>",
  "idNummer": "<KVNR or Telematik-ID from given authentication-certificate. Beispiel: 'X114428530'>",
  "amr": "["mfa", "sc", "pin"]",
  "iss": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "given_name": "<'givenName' from given authentication-certificate subject-DN. Beispiel: 'Juna'>",
  "nonce": "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: 'yb0mMrEos1wn5A6GfP6L'>",
  "aud": "eRezeptApp",
  "acr": "eidas-loa-high",
  "azp": "eRezeptApp",
  "auth_time": "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '1613408309'>",
  "exp": "<Duration of PT5M. Beispiel: '1613408609'>",
  "iat": "<Timestamp of the issueing of the token. Beispiel: '1613408309'>",
  "family_name": "<'surname' from given authentication-certificate subject-DN. Beispiel: 'Fuchs'>"
}
```

# Discovery Document

```
{
  "alg": "BP256R1",
  "kid": "discoveryKey",
  "x5c": "<Enthält das verwendete Signer-Zertifikat. Beispiel: '[
                                                              "MIICsTCCAligAwIBAgIH..."
                                                            ]'>"
}
{
  "authorization_endpoint": "<URL des Authorization Endpunkts.>",
  "alternative_authorization_endpoint": "http://localhost:56557/alt_response",
  "sso_endpoint": "<URL des Authorization Endpunkts.>",
  "pairing_endpoint": "http://localhost:56557/pairing",
  "token_endpoint": "<URL des Authorization Endpunkts.>",
  "uri_disc": "<URL des Discovery-Dokuments>",
  "issuer": "https://idp.zentral.idp.splitdns.ti-dienste.de",
  "jwks_uri": "<URL einer JWKS-Struktur mit allen vom Server verwendeten Schlüsseln>",
  "exp": "<Duration of PT24H. Beispiel: '1613494709'>",
  "nbf": "<token can not used before this timestamp. Beispiel: '1613408309'>",
  "iat": "<Timestamp of the issueing of the token. Beispiel: '1613408309'>",
  "puk_uri_auth": "<URL einer JWK-Struktur des Authorization Public-Keys>",
  "puk_uri_token": "<URL einer JWK-Struktur des Token Public-Keys>",
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


