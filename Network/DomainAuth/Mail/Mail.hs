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
import Data.Sequence (Seq, viewr, ViewR(..), empty)
import Network.DomainAuth.Mail.Types
import qualified Network.DomainAuth.Utils as B (empty)
import Network.DomainAuth.Utils hiding (empty)

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
fieldsWith :: [CanonFieldKey] -> Header -> Header
fieldsWith fieldsToFind fieldsToSearch = filter (\fld -> fieldSearchKey fld `elem` uniqueFieldsToFind) fieldsToSearch
  where 
    mkFieldsUnique [] = []
    mkFieldsUnique (x:xs) | x `elem` xs = mkFieldsUnique xs
                          | otherwise   = x : mkFieldsUnique xs
    uniqueFieldsToFind = mkFieldsUnique fieldsToFind

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
