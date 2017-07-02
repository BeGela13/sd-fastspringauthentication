module SD.FastSpringAuthentication
    ( fastSpringAuthentication
    ) where

import           Control.Monad          (guard)
import           Crypto.Hash.MD5        (hash)
import           Data.ByteString        (ByteString, append)
import qualified Data.ByteString        as B (concat, length)
import           Data.ByteString.Base16 (encode)
import           Data.List              (foldl', sortBy)
import           Data.Maybe             (mapMaybe)
import           Data.Map.Strict        (Map, fromList, toList)
import qualified Data.Map.Strict        as M (lookup)
import           Data.Text.Encoding     (decodeUtf8')
import           Data.Text.ICU          (CompareOption (CompareIgnoreCase))
import qualified Data.Text.ICU          as TI (compare)
import           Snap.Core              (urlDecode)

type SharedSecret = ByteString -- The “private key.”
type POSTParams = Map ByteString [ByteString]

fastSpringAuthentication :: SharedSecret -> POSTParams -> Bool
fastSpringAuthentication sharedSecret postParams =
    case fastSpringAuthMaybe sharedSecret postParams of
        Nothing -> False
        Just b  -> b

fastSpringAuthMaybe :: SharedSecret -> POSTParams -> Maybe Bool
fastSpringAuthMaybe sharedSecret postParams = do
    let sortedParams = sortWithKeys . consolidateValues $ toList postParams
    md5Hash <- listLookup "security_request_hash" sortedParams
    guard $ B.length md5Hash == 32
    let filteredParams = filter (\(k, _) -> k `compareBS`
                                            "security_request_hash" /= EQ)
                                sortedParams
    let concatData = (concatValues . urlDecodeValues $ filteredParams)
                         `append` sharedSecret
    let md5Hash' = encode . hash $ concatData
    guard $ B.length md5Hash' == 32
    guard $ compareBS md5Hash md5Hash' == EQ
    return True

listLookup :: Ord k => k -> [(k, v)] -> Maybe v
listLookup k l = M.lookup k (fromList l)

concatValues :: [(a, ByteString)] -> ByteString
concatValues l = foldl' lambda "" l
   where lambda accum (_, bs) = accum `append` bs

urlDecodeValues :: [(a, ByteString)] -> [(a, ByteString)]
urlDecodeValues l = mapMaybe func l
    where func (k, bs) = case urlDecode bs of
                             Nothing      -> Nothing
                             Just decoded -> Just (k, decoded)

consolidateValues :: [(ByteString, [ByteString])]
                         -> [(ByteString, ByteString)]
consolidateValues = map (\(key, values) -> (key, B.concat values))

sortWithKeys :: [(ByteString, ByteString)] -> [(ByteString, ByteString)]
sortWithKeys = sortBy compareFst

compareFst :: (ByteString, a) -> (ByteString, a) -> Ordering
compareFst t1 t2 = compareBS (fst t1) (fst t2)

compareBS :: ByteString -> ByteString -> Ordering
compareBS bs1 bs2 =
    let eText1 = decodeUtf8' bs1
        eText2 = decodeUtf8' bs2
        in case (eText1, eText2) of
            (Right text1, Right text2) ->  TI.compare [CompareIgnoreCase]
                                                      text1 text2
            _ -> EQ
