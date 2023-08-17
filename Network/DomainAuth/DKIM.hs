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
--           ,"        d=gmail.com; s=20221208; t=1692239637; x=1692844437;"
--           ,"        h=to:subject:message-id:date:from:mime-version:from:to:cc:subject"
--           ,"         :date:message-id:reply-to;"
--           ,"        bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=;"
--           ,"        b=ceWXhAaIcvcQCkqTELkw1Bk7v+0pwT8VjmmE49M2nNhXQqA/DXR/aRljXAxGFIm2eU"
--           ,"         qhHFwQBh9JHbDWXUpltPWisIEDVI+rgOZFRQ7s9OrhJ4Vfmi+Y9Tu3LqmrzvacjdRM2Z"
--           ,"         9RNfk4Wv1xk4jGas+JU0T296Z2BYOR5qxB5X/rmMhPNanKeZDmrhUOk+DWrbC+uJ0wcn"
--           ,"         P/jb76YBwTKBN1ySRrB0SdbruOIm0kYHYZoNMW/QWsR8f9PGthbAedCZrdjyixb7uXkz"
--           ,"         YmmGi6+XlLL3czZrj+RRrQlFn/xANIrE7sc0YYkhnehvBM6zZtgqesPflVbTlVEMMQg2"
--           ,"         N22A=="
--           ,"To: kazu@iij.ad.jp"
--           ,"Subject: test"
--           ,"Message-ID: <CAKipW39HW14nu7NN6xsdnNtu_PakrgeOAXo6agtkm=ScFmXqJQ@mail.gmail.com>"
--           ,"Date: Thu, 17 Aug 2023 11:33:46 +0900"
--           ,"From: Kazu Yamamoto <kazu.yamamoto@gmail.com>"
--           ,"MIME-Version: 1.0"
--           ,"Content-Type: text/plain; charset=\"UTF-8\""
--           ,""
--           ,"test"
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
