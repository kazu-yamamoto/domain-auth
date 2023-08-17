{-# LANGUAGE OverloadedStrings, TemplateHaskell #-}

module Test where

import qualified Data.ByteString.Char8 as BS (pack,unpack)
import Data.IP
import Network.DNS as DNS hiding (answer)
import Network.DomainAuth
import Network.DomainAuth.DK.Types
import Network.DomainAuth.DKIM.Btag
import Network.DomainAuth.DKIM.Types
import Network.DomainAuth.PRD.Lexer
import Network.DomainAuth.Pubkey.RSAPub
import Network.DomainAuth.Utils
import Test.Framework.Providers.HUnit
import Test.Framework.TH.Prime
import Test.HUnit
import Text.Appar.String

----------------------------------------------------------------

main :: IO ()
main = $(defaultMainGenerator)

----------------------------------------------------------------

case_ipv4 :: Assertion
case_ipv4 = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver ->
        runSPF defaultLimit resolver "mew.org" ip >>= (@?= DAPass)
  where
    ip = IPv4 . read $ "210.130.207.72"

case_ipv4_2 :: Assertion
case_ipv4_2 = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver ->
        runSPF defaultLimit resolver "example.org" ip >>= (@?= DATempError)
  where
    ip = IPv4 . read $ "192.0.2.1"

case_ipv6 :: Assertion
case_ipv6 = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver ->
        runSPF defaultLimit resolver "mew.org" ip >>= (@?= DAPass)
  where
    ip = IPv6 . read $ "2001:240:11e:c00::101"

case_redirect :: Assertion
case_redirect = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver ->
        runSPF defaultLimit resolver "gmail.com" ip >>= (@?= DAPass)
  where
    ip = IPv4 . read $ "72.14.192.1"

case_redirect2 :: Assertion
case_redirect2 = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver ->
        runSPF defaultLimit resolver "gmail.com" ip >>= (@?= DANeutral)
  where
    ip = IPv4 . read $ "72.14.128.1"

case_limit :: Assertion
case_limit = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver ->
        runSPF lim resolver "gmail.com" ip >>= (@?= DAPermError)
  where
    ip = IPv4 . read $ "72.14.192.1"
    lim = defaultLimit { ipv4_masklen = 24 }

case_limit2 :: Assertion
case_limit2 = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver ->
        runSPF defaultLimit resolver "nifty.com" ip >>= (@?= DAPass)
  where
    ip = IPv4 . read $ "202.248.236.1"

case_limit3 :: Assertion
case_limit3 = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver ->
        runSPF lim resolver "nifty.com" ip >>= (@?= DAPass)
  where
    ip = IPv4 . read $ "202.248.88.1"
    lim = defaultLimit { limit = 2 }

----------------------------------------------------------------

case_domain1 :: Assertion
case_domain1 = extractDomain "Alice Brown <alice.brown@example.com>" @?= Just "example.com"

case_domain2 :: Assertion
case_domain2 = extractDomain "\"Alice . Brown\" <alice.brown@example.com> (Nickname here)" @?= Just "example.com"

case_domain3 :: Assertion
case_domain3 = extractDomain "alice.brown@example.com" @?= Just "example.com"

case_domain4 :: Assertion
case_domain4 = extractDomain "Alice Brown <example.com>" @?= Nothing

----------------------------------------------------------------

maddr1,maddr2,maddr3,maddr4 :: RawFieldValue
maddr1 = "alice@alice.example.jp"
maddr2 = "bob@bob.example.jp"
maddr3 = "chris@chris.example.jp"
maddr4 = "dave@dave.example.jp"

case_from :: Assertion
case_from = decideFrom (pushPRD "from" maddr1 initialPRD) @?= answer
 where
   answer = Just "alice.example.jp"

case_prd1 :: Assertion
case_prd1 = decidePRD (pushPRD "from" maddr1 initialPRD) @?= answer
 where
   answer = Just "alice.example.jp"

case_prd2 :: Assertion
case_prd2 = decidePRD (pushPRD "from" maddr1
                     $ pushPRD "from" maddr1 initialPRD) @?= answer
 where
   answer = Nothing

case_prd3 :: Assertion
case_prd3 = decidePRD (pushPRD "sender" maddr2
                     $ pushPRD "from" maddr1
                     $ pushPRD "from" maddr1 initialPRD) @?= answer
 where
   answer = Just "bob.example.jp"

case_prd4 :: Assertion
case_prd4 = decidePRD (pushPRD "sender" maddr2
                     $ pushPRD "sender" maddr2
                     $ pushPRD "from" maddr1
                     $ pushPRD "from" maddr1 initialPRD) @?= answer
 where
   answer = Nothing

case_prd5 :: Assertion
case_prd5 = decidePRD (pushPRD "resent-from" maddr3
                     $ pushPRD "sender" maddr2
                     $ pushPRD "sender" maddr2
                     $ pushPRD "from" maddr1
                     $ pushPRD "from" maddr1 initialPRD) @?= answer
 where
   answer = Just "chris.example.jp"

case_prd6 :: Assertion
case_prd6 = decidePRD (pushPRD "resent-sender" maddr4
                     $ pushPRD "resent-from" maddr3
                     $ pushPRD "sender" maddr2
                     $ pushPRD "sender" maddr2
                     $ pushPRD "from" maddr1
                     $ pushPRD "from" maddr1 initialPRD) @?= answer
 where
   answer = Just "dave.example.jp"

case_prd7 :: Assertion
case_prd7 = decidePRD (pushPRD "resent-sender" maddr4
                     $ pushPRD "resent-from" maddr3
                     $ pushPRD "sender" maddr2
                     $ pushPRD "received" "dummy"
                     $ pushPRD "from" maddr1 initialPRD) @?= answer
 where
   answer = Just "dave.example.jp"

case_prd8 :: Assertion
case_prd8 = decidePRD (pushPRD "resent-sender" maddr4
                     $ pushPRD "received" "dummy"
                     $ pushPRD "resent-from" maddr3
                     $ pushPRD "sender" maddr2
                     $ pushPRD "from" maddr1 initialPRD) @?= answer
  where
   answer = Just "chris.example.jp"

case_prd9 :: Assertion
case_prd9 = decidePRD (pushPRD "received" "dummy"
                     $ pushPRD "resent-sender" maddr4
                     $ pushPRD "resent-from" maddr3
                     $ pushPRD "sender" maddr2
                     $ pushPRD "from" maddr1 initialPRD) @?= answer
 where
   answer = Just "dave.example.jp"

----------------------------------------------------------------

case_structured1 :: Assertion
case_structured1 = parse structured inp @?= out
  where
    inp = "From: Kazu Yamamoto (=?iso-2022-jp?B?GyRCOzNLXE9CSScbKEI=?=)\n <kazu@example.net>"
    out = Just ["From",":","Kazu","Yamamoto","<","kazu","@","example",".","net",">"]

case_structured2 :: Assertion
case_structured2 = parse structured inp @?= out
  where
    inp = "To:A Group(Some people)\n      :Chris Jones <c@(Chris's host.)public.example>,\n          joe@example.org,\n   John <jdoe@one.test> (my dear friend); (the end of the group)\n"
    out = Just ["To",":","A","Group",":","Chris","Jones","<","c","@","public",".","example",">",",","joe","@","example",".","org",",","John","<","jdoe","@","one",".","test",">",";"]

case_structured3 :: Assertion
case_structured3 = parse structured inp @?= out
  where
    inp = "Date: Thu,\n      13\n        Feb\n          1969\n      23:32\n               -0330 (Newfoundland Time)\n"
    out = Just ["Date",":","Thu",",","13","Feb","1969","23",":","32","-0330"]

case_structured4 :: Assertion
case_structured4 = parse structured inp @?= out
  where
    inp = "From: Pete(A nice \\) chap) <pete(his account)@silly.test(his host)>\n"
    out = Just ["From",":","Pete","<","pete","@","silly",".","test",">"]

----------------------------------------------------------------

case_parse :: Assertion
case_parse = parseTaggedValue input @?= output
  where
    input = " k = rsa ; p= MIGfMA0G; n=A 1024 bit key;"
    output = [("k","rsa"),("p","MIGfMA0G"),("n","A1024bitkey")]

case_parse2 :: Assertion
case_parse2 = parseTaggedValue input @?= output
  where
    input = " k = \nrsa ;\n p= MIGfMA0G;\n n=A 1024 bit key"
    output = [("k","rsa"),("p","MIGfMA0G"),("n","A1024bitkey")]

----------------------------------------------------------------

case_lookup_yahoo :: Assertion
case_lookup_yahoo = do
    rs <- DNS.makeResolvSeed DNS.defaultResolvConf
    pub0 <- readFile "data/yahoo.pub"
    DNS.withResolver rs $ \resolver -> do
        Just pub1 <- lookupPublicKey' resolver "dk200510._domainkey.yahoo.co.jp"
        BS.unpack pub1 @?= init pub0 -- removing "\n"

case_lookup_gmail :: Assertion
case_lookup_gmail = do
    rs <- DNS.makeResolvSeed DNS.defaultResolvConf
    pub0 <- readFile "data/gmail.pub"
    DNS.withResolver rs $ \resolver -> do
        Just pub1 <- lookupPublicKey' resolver "gamma._domainkey.gmail.com"
        BS.unpack pub1 @?= init pub0 -- removing "\n"

case_lookup_iij :: Assertion
case_lookup_iij = do
    rs <- DNS.makeResolvSeed DNS.defaultResolvConf
    pub0 <- readFile "data/iij.pub"
    DNS.withResolver rs $ \resolver -> do
        Just pub1 <- lookupPublicKey' resolver "omgo1._domainkey.iij.ad.jp"
        BS.unpack pub1 @?= init pub0 -- removing "\n"

----------------------------------------------------------------

case_dk_field :: Assertion
case_dk_field = parseDK inp @?= out
  where
    inp = "a=rsa-sha1; s=brisbane; d=football.example.com;\n  c=simple; q=dns;\n  b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZ\n    VoG4ZHRNiYzR;"
    out = Just DK {dkAlgorithm = DK_RSA_SHA1, dkSignature = "dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR", dkCanonAlgo = DK_SIMPLE, dkDomain0 = "football.example.com", dkFields = Nothing, dkSelector0 = "brisbane"}

case_dkim_field :: Assertion
case_dkim_field = parseDKIM inp @?= out
  where
   inp = "v=1; a=rsa-sha256; s=brisbane; d=example.com;\n         c=relaxed/simple; q=dns/txt; i=joe@football.example.com;\n         h=Received : From : To : Subject : Date : Message-ID;\n         bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\n         b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB\n           4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut\n           KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV\n           4bmp/YzhwvcubU4=;"
   out = Just DKIM {dkimVersion = "1", dkimSigAlgo = RSA_SHA256, dkimSignature = "AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHutKVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV4bmp/YzhwvcubU4=", dkimBodyHash = "2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=", dkimHeaderCanon = DKIM_RELAXED, dkimBodyCanon = DKIM_SIMPLE, dkimDomain0 = "example.com", dkimFields = ["received","from","to","subject","date","message-id"], dkimLength = Nothing, dkimSelector0 = "brisbane"}

case_dkim_field2 :: Assertion
case_dkim_field2 = parseDKIM inp @?= out
  where
   inp = "v=1; a=rsa-sha256; s=brisbane; d=example.com;\n         q=dns/txt; i=joe@football.example.com;\n         h=Received : From : To : Subject : Date : Message-ID;\n         bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\n         b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB\n           4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut\n           KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV\n           4bmp/YzhwvcubU4=;"
   out = Just DKIM {dkimVersion = "1", dkimSigAlgo = RSA_SHA256, dkimSignature = "AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHutKVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV4bmp/YzhwvcubU4=", dkimBodyHash = "2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=", dkimHeaderCanon = DKIM_SIMPLE, dkimBodyCanon = DKIM_SIMPLE, dkimDomain0 = "example.com", dkimFields = ["received","from","to","subject","date","message-id"], dkimLength = Nothing, dkimSelector0 = "brisbane"}

case_dkim_fields_with :: Assertion
case_dkim_fields_with = fieldsWith ["from","to","subject","date","message-id"] inp @?= out
  where
    inp = [Field "from" "From" "foo",Field "to" "To" "bar",Field "subject" "Subject" "baz",Field "date" "Date" "qux",Field "message-id" "Message-Id" "quux", Field "received" "Received" "fiz", Field "filtered-out" "Filtered-Out" "buzz", Field "not-needed" "Not-Needed" "fizz"]
    out = [Field "from" "From" "foo",Field "to" "To" "bar",Field "subject" "Subject" "baz",Field "date" "Date" "qux",Field "message-id" "Message-Id" "quux"]

----------------------------------------------------------------

case_dk_yahoo :: Assertion
case_dk_yahoo = do
    mail <- readMail "data/yahoo"
    rs <- DNS.makeResolvSeed DNS.defaultResolvConf
    DNS.withResolver rs $ \resolver -> do
        res <- runDK resolver mail
        res @?= DAPass

case_dk_gmail :: Assertion
case_dk_gmail = do
    mail <- readMail "data/gmail"
    rs <- DNS.makeResolvSeed DNS.defaultResolvConf
    DNS.withResolver rs $ \resolver -> do
        res <- runDK resolver mail
        res @?= DAPass

----------------------------------------------------------------

case_dkim_iij :: Assertion
case_dkim_iij = do
    mail <- readMail "data/iij"
    rs <- DNS.makeResolvSeed DNS.defaultResolvConf
    DNS.withResolver rs $ \resolver -> do
        res <- runDKIM resolver mail
        res @?= DAPass

case_dkim_gmail :: Assertion
case_dkim_gmail = do
    mail <- readMail "data/gmail"
    rs <- DNS.makeResolvSeed DNS.defaultResolvConf
    DNS.withResolver rs $ \resolver -> do
        res <- runDKIM resolver mail
        res @?= DAPass

case_dkim_nifty :: Assertion
case_dkim_nifty = do
    mail <- readMail "data/nifty"
    rs <- DNS.makeResolvSeed DNS.defaultResolvConf
    DNS.withResolver rs $ \resolver -> do
        res <- runDKIM resolver mail
        res @?= DAPass

case_dkim_iij4u :: Assertion
case_dkim_iij4u = do
    mail <- readMail "data/iij4u"
    rs <- DNS.makeResolvSeed DNS.defaultResolvConf
    DNS.withResolver rs $ \resolver -> do
        res <- runDKIM resolver mail
        res @?= DAPass

----------------------------------------------------------------

case_mail :: Assertion
case_mail = getMail inp @?= out
  where
    inp = BS.pack "from: val\nto: val\n\nbody"
    out = finalizeMail
        $ pushBody "body"
        $ pushField "to" "val"
        $ pushField "from" "val"
        initialXMail

case_mail2 :: Assertion
case_mail2 = getMail inp @?= out
  where
    inp = BS.pack "from: val\tval\nto: val\n\nbody"
    out = finalizeMail
        $ pushBody "body"
        $ pushField "to" "val"
        $ pushField "from" "val\tval"
        initialXMail

case_mail3 :: Assertion
case_mail3 = getMail inp @?= out
  where
    inp = BS.pack "from: val\nto: val\n"
    out = finalizeMail
        $ pushBody ""
        $ pushField "to" "val"
        $ pushField "from" "val"
        initialXMail

----------------------------------------------------------------

case_dkim_btag :: Assertion
case_dkim_btag = removeBtagValue inp @?= out
  where
    inp = "DKIM-Signature: a=rsa-sha256; d=example.net; s=brisbane;\n   c=simple; q=dns/txt; i=@eng.example.net;\n   t=1117574938; x=1118006938;\n   h=from:to:subject:date;\n   z=From:foo@eng.example.net|To:joe@example.com|\n     Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700;\n   bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;\n   b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZ\n            VoG4ZHRNiYzR;\n"
    out = "DKIM-Signature: a=rsa-sha256; d=example.net; s=brisbane;\n   c=simple; q=dns/txt; i=@eng.example.net;\n   t=1117574938; x=1118006938;\n   h=from:to:subject:date;\n   z=From:foo@eng.example.net|To:joe@example.com|\n     Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700;\n   bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;\n   b=;\n"

----------------------------------------------------------------

case_blines :: Assertion
case_blines = blines inp @?= out
  where
    inp = "foo\r\n\r\nbar\r\nbaz"
    out = ["foo","","bar","baz"]

case_blines2 :: Assertion
case_blines2 = blines inp @?= out
  where
    inp = "foo\r\n"
    out = ["foo"]

----------------------------------------------------------------
