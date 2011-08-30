{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.Mail.Mail where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS
import qualified Data.Foldable as F (foldr)
import Data.List
import Data.Sequence (Seq, viewr, ViewR(..), empty)
import Network.DomainAuth.Mail.Types
import Network.DomainAuth.Utils

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

{-
  RFC 4871 is ambiguous, so implement only normal case.
-}
-- | Obtaining all fields with DKIM algorithm.
fieldsWith :: [CanonFieldKey] -> Header -> Header
fieldsWith [] _ = []
fieldsWith _ [] = []
fieldsWith (k:ks) is
  | fs == []  = fieldsWith (k:ks) (tail is')
  | otherwise = take len (reverse fs) ++ fieldsWith ks' is'
  where
    (fs,is') = span (\fld -> fieldSearchKey fld == k) is
    (kx,ks') = span (==k) ks
    len = length kx + 1 -- including k

----------------------------------------------------------------

isKeyOf :: CanonFieldKey -> Field -> Bool
isKeyOf key fld = fieldSearchKey fld == key

isNotKeyOf :: CanonFieldKey -> Field -> Bool
isNotKeyOf key fld = fieldSearchKey fld /= key

----------------------------------------------------------------

-- | Obtaining folded (raw) field value.
fieldValueFolded :: Field -> RawFieldValue
fieldValueFolded = concatCRLF . fieldValue

-- | Obtaining unfolded (removing CRLF) field value.
fieldValueUnfolded :: Field -> RawFieldValue
fieldValueUnfolded = BS.concat . fieldValue

----------------------------------------------------------------

-- | Obtaining body.
fromBody :: Body -> ByteString
fromBody = fromBodyWith id

-- | Obtaining body with a canonicalization function.
fromBodyWith :: (ByteString -> ByteString) -> Body -> ByteString
fromBodyWith modify = F.foldr (appendCRLFWith modify) ""

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
