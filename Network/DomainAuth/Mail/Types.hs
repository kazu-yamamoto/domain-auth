module Network.DomainAuth.Mail.Types where

import qualified Data.ByteString.Lazy.Char8 as L
import Data.Char
import Data.Sequence

----------------------------------------------------------------
-- | Type for raw e-mail message.
type RawMail = L.ByteString
type RawHeader = L.ByteString
type RawBody = L.ByteString
type RawField = L.ByteString
-- | Field key for raw e-mail message.
type RawFieldKey = L.ByteString
-- | Field value for raw e-mail message.
type RawFieldValue = L.ByteString
-- | Body chunk for raw e-mail message.
type RawBodyChunk = L.ByteString

----------------------------------------------------------------

{-|
  Type for parsed e-mail message.
-}
data Mail = Mail {
    mailHeader :: Header
  , mailBody :: Body
  } deriving (Eq,Show)

{-|
  Header type for parsed e-mail message.
-}
type Header = [Field]

{-|
  Field type for parsed e-mail message.
-}
data Field = Field {
    fieldSearchKey :: CanonFieldKey
  , fieldKey       :: FieldKey
  , fieldValue     :: FieldValue
  } deriving (Eq,Show)

-- | Type for canonicalized field key of parsed e-mail message.
type CanonFieldKey = L.ByteString
-- | Type for field key of parsed e-mail message.
type FieldKey = L.ByteString
-- | Type for field value of parsed e-mail message.
type FieldValue = [L.ByteString]
-- | Type for body of parsed e-mail message.
type Body = Seq L.ByteString

----------------------------------------------------------------

-- | Canonicalizing 'FieldKey' for search.
canonicalizeKey :: FieldKey -> CanonFieldKey
canonicalizeKey = L.map toLower
