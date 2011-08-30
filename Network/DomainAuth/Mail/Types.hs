module Network.DomainAuth.Mail.Types where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS
import Data.Char
import Data.Sequence

----------------------------------------------------------------
-- | Type for raw e-mail message.
type RawMail = ByteString
type RawHeader = ByteString
type RawBody = ByteString
type RawField = ByteString
-- | Field key for raw e-mail message.
type RawFieldKey = ByteString
-- | Field value for raw e-mail message.
type RawFieldValue = ByteString
-- | Body chunk for raw e-mail message.
type RawBodyChunk = ByteString

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
type CanonFieldKey = ByteString
-- | Type for field key of parsed e-mail message.
type FieldKey = ByteString
-- | Type for field value of parsed e-mail message.
type FieldValue = [ByteString]
-- | Type for body of parsed e-mail message.
type Body = Seq ByteString

----------------------------------------------------------------

-- | Canonicalizing 'FieldKey' for search.
canonicalizeKey :: FieldKey -> CanonFieldKey
canonicalizeKey = BS.map toLower
