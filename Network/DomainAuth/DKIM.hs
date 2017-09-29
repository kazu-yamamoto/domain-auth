{-# LANGUAGE OverloadedStrings #-}

-- | A library for DKIM (<http://www.ietf.org/rfc/rfc6376.txt>).
--   Currently, only receiver side is implemented.

module Network.DomainAuth.DKIM (
  -- * Documentation
  -- ** Authentication with DKIM
    runDKIM, runDKIM'
  -- ** Parsing DKIM-Signature:
  , parseDKIM
  , DKIM, dkimDomain, dkimSelector
  -- ** Field key for DKIM-Signature:
  , dkimFieldKey
  ) where

import qualified Data.ByteString as BS
import Network.DNS as DNS (Resolver)
import Network.DomainAuth.DKIM.Parser
import Network.DomainAuth.DKIM.Types
import Network.DomainAuth.DKIM.Verify
import Network.DomainAuth.Mail
import Network.DomainAuth.Pubkey.RSAPub
import Network.DomainAuth.Types

-- $setup
-- >>> import Network.DNS
-- >>> import Data.ByteString.Char8 as BS8

-- | Verifying 'Mail' with DKIM.
--
-- >>> rs <- makeResolvSeed defaultResolvConf
-- >>> :{
-- let lst = ["DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;"
--           ,"        d=gmail.com; s=20161025;"
--           ,"        h=mime-version:from:date:message-id:subject:to;"
--           ,"        bh=IQB23UrpTWE7dPV0Ebeqy3ZJyCILT/tw2Ixhmh83FJ0=;"
--           ,"        b=BCZrZwEnJfrdbbNqM+bWHeDrdHKvc6DvjafGCDndUUkHPbfVvvx2RTYfkC3LT1uCZC"
--           ,"         7vzKmucESLK5PVh4mAGNQjHDmdvhq7GIubOVK8Uoq+MpjZ321SwNI7rck/uLq512bfvO"
--           ,"         NU9nYcUGNIKh+rho6V8XHX/REsfE+a8jGUvywZgV5IoORfTvejEluuy360PN0rAjSmi3"
--           ,"         j5WRFV7XR5pCzAN78hmsUaTzf8zdwQwIlSsnUylnlRmc97xU5Ou3VBzxBV+ScXZsX5jI"
--           ,"         TNv+ujuZcoO0fS0zm7UwmcOzXb01cQpBDqHK8cBvEdQ4+8LSx/Nf1UaOBrecw6GiwN23"
--           ,"         BFBg=="
--           ,"MIME-Version: 1.0"
--           ,"Received: by 10.37.15.133 with HTTP; Wed, 20 Sep 2017 01:19:02 -0700 (PDT)"
--           ,"From: Kazu Yamamoto <kazu.yamamoto@gmail.com>"
--           ,"Date: Wed, 20 Sep 2017 17:19:02 +0900"
--           ,"Message-ID: <CAKipW39GqeTzzQzB6WhM86_P==xTHwioa5gE=wZZ96fzf1j3Vw@mail.gmail.com>"
--           ,"Subject: test for DKIM"
--           ,"To: Kazu Yamamoto <kazu@iij.ad.jp>"
--           ,"Content-Type: text/plain; charset=\"UTF-8\""
--           ,""
--           ,"this is test."
--           ,""
--           ]
--     mail = getMail $ BS8.intercalate "\r\n" lst
-- in withResolver rs $ \rslv -> runDKIM rslv mail
-- :}
-- pass
runDKIM :: Resolver -> Mail -> IO DAResult
runDKIM resolver mail = dkim1
  where
    dkim1       = maybe (return DANone)      dkim2 $ lookupField dkimFieldKey (mailHeader mail)
    dkim2 dkimv = maybe (return DAPermError) dkim3 $ parseDKIM (fieldValueUnfolded dkimv)
    dkim3       = runDKIM' resolver mail

-- | Verifying 'Mail' with DKIM. The value of DKIM-Signature:
--   should be parsed beforehand.
runDKIM' :: Resolver -> Mail -> DKIM -> IO DAResult
runDKIM' resolver mail dkim = maybe DATempError (verify mail dkim) <$> pub
  where
    pub = lookupPublicKey resolver dom
    dom = dkimSelector dkim +++ "._domainkey." +++ dkimDomain dkim
    verify m d p = if verifyDKIM m d p then DAPass else DAFail
    (+++) = BS.append
