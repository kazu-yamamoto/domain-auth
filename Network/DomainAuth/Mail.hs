-- | A library to parse e-mail messages both from a file and Milter(<https://www.milter.org/>).

module Network.DomainAuth.Mail (
  -- * Documentation
  -- ** Types for raw e-mail message
    RawMail
  , RawFieldKey
  , RawFieldValue
  , RawBodyChunk
  -- ** Types for parsed e-mail message
  , Mail(..), Header, Field(..), CanonFieldKey, FieldKey, FieldValue, Body
  , canonicalizeKey
  -- ** Obtaining 'Mail'
  , readMail, getMail
  -- ** Obtaining 'Mail' incrementally.
  , XMail(..)
  , initialXMail
  , pushField, pushBody, finalizeMail
  -- ** Functions to manipulate 'Header'
  , lookupField
  , fieldsFrom
  , fieldsAfter
  , fieldsWith
  -- ** Functions to manipulate 'Field'
  , fieldValueFolded
  , fieldValueUnfolded
  -- ** Functions to manipulate 'Body'
  , isEmpty
  , fromBody
  , fromBodyWith
  , removeTrailingEmptyLine
  -- ** Special function for DomainKeys and DKIM
  , parseTaggedValue
  ) where

import Network.DomainAuth.Mail.Mail
import Network.DomainAuth.Mail.Parser
import Network.DomainAuth.Mail.Types
import Network.DomainAuth.Mail.XMail
