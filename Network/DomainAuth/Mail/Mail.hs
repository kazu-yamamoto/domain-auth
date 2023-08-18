{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.Mail.Mail (
    lookupField
  , fieldsFrom
  , fieldsAfter
  , fieldsWith
  , fieldValueFolded
  , fieldValueUnfolded
  , fromBody
  , fromBodyWith
  , removeTrailingEmptyLine
  ) where

import Data.ByteString (ByteString)
import Data.ByteString.Builder (Builder)
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as BL
import qualified Data.Foldable as F (foldr)
import Data.List
import Data.Maybe (catMaybes)
import Data.Sequence (Seq, viewr, ViewR(..), empty)
import Network.DomainAuth.Mail.Types
import qualified Network.DomainAuth.Utils as B (empty)
import Network.DomainAuth.Utils hiding (empty)

-- $setup
-- >>> :set -XOverloadedStrings
-- >>> import Data.ByteString.Char8

----------------------------------------------------------------

-- | Looking up 'Field' from 'Header' with 'FieldKey'.
lookupField :: FieldKey -> Header -> Maybe Field
lookupField key hdr = find (ckey `isKeyOf`) hdr
  where
    ckey = canonicalizeKey key

-- | Obtaining the 'Field' of 'FieldKey' and all fields under 'FieldKey'.
fieldsFrom :: FieldKey -> Header -> Header
fieldsFrom key = dropWhile (ckey `isNotKeyOf`)
  where
    ckey = canonicalizeKey key

-- | Obtaining all fields under 'FieldKey'.
fieldsAfter :: FieldKey -> Header -> Header
fieldsAfter key = safeTail . fieldsFrom key
  where
    safeTail [] = []
    safeTail xs = tail xs

-- RFC 4871 is ambiguous, so implement only normal case.

-- | Obtaining all fields with DKIM algorithm.
--
-- >>> fieldsWith ["from","to","subject","date","message-id"] [Field "from" "From" ["foo"],Field "to" "To" ["bar"],Field "subject" "Subject" ["baz"],Field "date" "Date" ["qux"],Field "message-id" "Message-Id" ["quux"], Field "received" "Received" ["fiz"], Field "filtered-out" "Filtered-Out" ["buzz"], Field "not-needed" "Not-Needed" ["fizz"]]
-- [Field {fieldSearchKey = "from", fieldKey = "From", fieldValue = ["foo"]},Field {fieldSearchKey = "to", fieldKey = "To", fieldValue = ["bar"]},Field {fieldSearchKey = "subject", fieldKey = "Subject", fieldValue = ["baz"]},Field {fieldSearchKey = "date", fieldKey = "Date", fieldValue = ["qux"]},Field {fieldSearchKey = "message-id", fieldKey = "Message-Id", fieldValue = ["quux"]}]
fieldsWith :: [CanonFieldKey] -> Header -> Header
fieldsWith kx hx = catMaybes $ enm kx hx (\k h -> k == fieldSearchKey h)

-- >>> enm [1,2,3] [1,1,2,2,2,3,4,5] (==)
-- [Just 1,Just 2,Just 3]
-- >>> enm [1,1,2,3] [1,1,2,2,2,3,4,5] (==)
-- [Just 1,Just 1,Just 2,Just 3]
-- >>> enm [1,1,1,2,3] [1,1,2,2,2,3,4,5] (==)
-- [Just 1,Just 1,Nothing,Just 2,Just 3]
enm :: [a] -> [b] -> (a -> b -> Bool) -> [Maybe b]
enm [] _ _ = []
enm _ [] _ = []
enm (k:kx) hs0 eq = case fnd (eq k) hs0 of
  Nothing -> Nothing : enm kx hs0 eq
  Just (x,hs) -> Just x : enm kx hs eq

-- >>> fnd (== 1) [1,2,3]
-- Just (1,[2,3])
-- >>> fnd (== 2) [1,2,3]
-- Just (2,[1,3])
-- >>> fnd (== 3) [1,2,3]
-- Just (3,[1,2])
-- >>> fnd (== 4) [1,2,3]
-- Nothing
fnd :: (a -> Bool) -> [a] -> Maybe (a,[a])
fnd _ [] = Nothing
fnd p (x:xs)
  | p x = Just (x, xs)
  | otherwise = case fnd p xs of
      Nothing -> Nothing
      Just (y,ys) -> Just (y, x:ys)

----------------------------------------------------------------

isKeyOf :: CanonFieldKey -> Field -> Bool
isKeyOf key fld = fieldSearchKey fld == key

isNotKeyOf :: CanonFieldKey -> Field -> Bool
isNotKeyOf key fld = fieldSearchKey fld /= key

----------------------------------------------------------------

-- | Obtaining folded (raw) field value.
fieldValueFolded :: Field -> RawFieldValue
fieldValueFolded = BL.toStrict . BB.toLazyByteString . concatCRLF . fieldValue

-- | Obtaining unfolded (removing CRLF) field value.
fieldValueUnfolded :: Field -> RawFieldValue
fieldValueUnfolded = BS8.concat . fieldValue

----------------------------------------------------------------

-- | Obtaining body.
fromBody :: Body -> Builder
fromBody = fromBodyWith id

-- | Obtaining body with a canonicalization function.
fromBodyWith :: (ByteString -> ByteString) -> Body -> Builder
fromBodyWith modify = F.foldr (appendCRLFWith modify) B.empty

-- | Removing trailing empty lines.
removeTrailingEmptyLine :: Body -> Body
removeTrailingEmptyLine = dropWhileR (=="")

-- dropWhileR is buggy, sigh.
dropWhileR :: (a -> Bool) -> Seq a -> Seq a
dropWhileR p xs = case viewr xs of
    EmptyR        -> empty
    xs' :> x
      | p x       -> dropWhileR p xs'
      | otherwise -> xs
