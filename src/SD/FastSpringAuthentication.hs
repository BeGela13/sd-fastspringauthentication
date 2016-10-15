module SD.FastSpringAuthentication
    ( fastSpringAuthentication
    ) where

import qualified Control.Monad          as MO
import qualified Crypto.Hash.MD5        as HM
import qualified Data.ByteString        as B
import qualified Data.ByteString.Base16 as BB
import qualified Data.List              as L
import qualified Data.Maybe             as DM
import qualified Data.Map.Strict        as M
import qualified Data.Text.Encoding     as TE
import qualified Data.Text.ICU          as TI
import qualified Snap.Core              as SC

type SharedSecret = B.ByteString -- The “private key.”
type POSTParams = M.Map B.ByteString [B.ByteString]

fastSpringAuthentication :: SharedSecret -> POSTParams -> Bool
fastSpringAuthentication sharedSecret postParams =
    case fastSpringAuthMaybe sharedSecret postParams of
        Nothing -> False
        Just b  -> b

fastSpringAuthMaybe :: SharedSecret -> POSTParams -> Maybe Bool
fastSpringAuthMaybe sharedSecret postParams = do
    let sortedParams = sortWithKeys . consolidateValues $ M.toList postParams
    md5Hash <- listLookup "security_request_hash" sortedParams
    MO.guard $ B.length md5Hash == 32
    let filteredParams = filter (\(k, _) -> k `compareBS`
                                            "security_request_hash" /= EQ)
                                sortedParams
    let concatData = (concatValues . urlDecodeValues $ filteredParams)
                         `B.append` sharedSecret
    let md5Hash' = BB.encode . HM.hash $ concatData
    MO.guard $ B.length md5Hash' == 32
    MO.guard $ compareBS md5Hash md5Hash' == EQ
    return True

listLookup :: Ord k => k -> [(k, v)] -> Maybe v
listLookup k l = M.lookup k (M.fromList l)

concatValues :: [(a, B.ByteString)] -> B.ByteString
concatValues l = L.foldl' lambda "" l
   where lambda accum (_, bs) = accum `B.append` bs

urlDecodeValues :: [(a, B.ByteString)] -> [(a, B.ByteString)]
urlDecodeValues l = DM.mapMaybe func l
    where func (k, bs) = case SC.urlDecode bs of
                             Nothing      -> Nothing
                             Just decoded -> Just (k, decoded)

consolidateValues :: [(B.ByteString, [B.ByteString])]
                         -> [(B.ByteString, B.ByteString)]
consolidateValues = map (\(key, values) -> (key, B.concat values))

sortWithKeys :: [(B.ByteString, B.ByteString)] -> [(B.ByteString, B.ByteString)]
sortWithKeys = L.sortBy compareFst

compareFst :: (B.ByteString, a) -> (B.ByteString, a) -> Ordering
compareFst t1 t2 = compareBS (fst t1) (fst t2)

compareBS :: B.ByteString -> B.ByteString -> Ordering
compareBS bs1 bs2 =
    let eText1 = TE.decodeUtf8' bs1
        eText2 = TE.decodeUtf8' bs2
        in case (eText1, eText2) of
            (Right text1, Right text2) ->  TI.compare [TI.CompareIgnoreCase]
                                                      text1 text2
            _ -> EQ
