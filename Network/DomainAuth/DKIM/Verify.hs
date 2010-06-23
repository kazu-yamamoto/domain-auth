{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.DKIM.Verify where

import Network.DomainAuth.Mail

----------------------------------------------------------------

dkimFieldKey :: CanonFieldKey
dkimFieldKey = "dkim-signature"
