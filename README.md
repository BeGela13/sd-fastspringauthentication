**Note**: [shlok](https://github.com/shlok) created this for use in personal
projects. Use at your own risk.

Exports the module `SD.FastSpringAuthentication`, which exports one function:
`fastSpringAuthentication`.

    import Data.ByteString
    import Data.Map.Strict
    type SharedSecret = ByteString -- The “private key.”
    type POSTParams = Map ByteString [ByteString]
    fastSpringAuthentication :: SharedSecret -> POSTParams -> Bool

This function can be used to authenticate [FastSpring](https://fastspring.com)’s
access to your license key generation POST endpoint. `SharedSecret` is the
“private key” shown in your FastSpring account. `POSTParams` are the POST
parameters that FastSpring sends to your endpoint. The function returns `True`
on successful authentication. (The `POSTParams` type is based on the `Params`
type in `Snap.Core` because [shlok](https://github.com/shlok) plans on using
this function through the [Snap framework](http://snapframework.com).)

This repository was created as a part of [shlok](https://github.com/shlok)’s
efforts in 2016 to migrate all of his websites and web apps to be powered by the
[Snap framework](http://snapframework.com).
