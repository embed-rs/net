// from https://github.com/tamird/bitflags/blob/232b55efff2d1cb53b165b316f16acf5784618d5/src/lib.rs

// Copyright 2014 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Re-export libstd/libcore using an alias so that the macros can work in no_std
// crates while remaining compatible with normal crates.
#[doc(hidden)]
pub extern crate core as _core;

#[macro_export]
macro_rules! bitflags {
    ($(#[$attr:meta])* pub struct $BitFlags:ident: $T:ty {
        $($(#[$Flag_attr:meta])* const $Flag:ident = $value:expr;)+
    }) => {
        #[derive(Copy, PartialEq, Eq, Clone, PartialOrd, Ord, Hash)]
        $(#[$attr])*
        pub struct $BitFlags {
            bits: $T,
        }

        __impl_bitflags! {
            struct $BitFlags: $T {
                $($(#[$Flag_attr])* const $Flag = $value;)+
            }
        }
    };
    ($(#[$attr:meta])* struct $BitFlags:ident: $T:ty {
        $($(#[$Flag_attr:meta])* const $Flag:ident = $value:expr;)+
    }) => {
        #[derive(Copy, PartialEq, Eq, Clone, PartialOrd, Ord, Hash)]
        $(#[$attr])*
        struct $BitFlags {
            bits: $T,
        }

        __impl_bitflags! {
            struct $BitFlags: $T {
                $($(#[$Flag_attr])* const $Flag = $value;)+
            }
        }

    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __impl_bitflags {
    (struct $BitFlags:ident: $T:ty {
        $($(#[$Flag_attr:meta])* const $Flag:ident = $value:expr;)+
    }) => {
        impl $crate::bitflags::_core::fmt::Debug for $BitFlags {
            fn fmt(&self, f: &mut $crate::bitflags::_core::fmt::Formatter) -> $crate::bitflags::_core::fmt::Result {
                // This convoluted approach is to handle #[cfg]-based flag
                // omission correctly. For example it needs to support:
                //
                //    #[cfg(unix)] const A: Flag = /* ... */;
                //    #[cfg(windows)] const B: Flag = /* ... */;

                // Unconditionally define a check for every flag, even disabled
                // ones.
                #[allow(non_snake_case)]
                trait __BitFlags {
                    $(
                        fn $Flag(&self) -> bool { false }
                    )+
                }

                // Conditionally override the check for just those flags that
                // are not #[cfg]ed away.
                impl __BitFlags for $BitFlags {
                    $(
                        $(#[$Flag_attr])*
                        fn $Flag(&self) -> bool {
                            self.bits & Self::$Flag.bits == Self::$Flag.bits
                        }
                    )+
                }

                let mut first = true;
                $(
                    if <$BitFlags as __BitFlags>::$Flag(self) {
                        if !first {
                            try!(f.write_str(" | "));
                        }
                        first = false;
                        try!(f.write_str(stringify!($Flag)));
                    }
                )+
                if first {
                    try!(f.write_str("(empty)"));
                }
                Ok(())
            }
        }
        impl $crate::bitflags::_core::fmt::Binary for $BitFlags {
            fn fmt(&self, f: &mut $crate::bitflags::_core::fmt::Formatter) -> $crate::bitflags::_core::fmt::Result {
                $crate::bitflags::_core::fmt::Binary::fmt(&self.bits, f)
            }
        }
        impl $crate::bitflags::_core::fmt::Octal for $BitFlags {
            fn fmt(&self, f: &mut $crate::bitflags::_core::fmt::Formatter) -> $crate::bitflags::_core::fmt::Result {
                $crate::bitflags::_core::fmt::Octal::fmt(&self.bits, f)
            }
        }
        impl $crate::bitflags::_core::fmt::LowerHex for $BitFlags {
            fn fmt(&self, f: &mut $crate::bitflags::_core::fmt::Formatter) -> $crate::bitflags::_core::fmt::Result {
                $crate::bitflags::_core::fmt::LowerHex::fmt(&self.bits, f)
            }
        }
        impl $crate::bitflags::_core::fmt::UpperHex for $BitFlags {
            fn fmt(&self, f: &mut $crate::bitflags::_core::fmt::Formatter) -> $crate::bitflags::_core::fmt::Result {
                $crate::bitflags::_core::fmt::UpperHex::fmt(&self.bits, f)
            }
        }

        #[allow(dead_code)]
        impl $BitFlags {
            $($(#[$Flag_attr])* pub const $Flag: $BitFlags = $BitFlags { bits: $value };)+

            /// Returns an empty set of flags.
            #[inline]
            pub fn empty() -> $BitFlags {
                $BitFlags { bits: 0 }
            }

            /// Returns the set containing all flags.
            #[inline]
            pub fn all() -> $BitFlags {
                // See `Debug::fmt` for why this approach is taken.
                #[allow(non_snake_case)]
                trait __BitFlags {
                    $(
                        fn $Flag() -> $T { 0 }
                    )+
                }
                impl __BitFlags for $BitFlags {
                    $(
                        $(#[$Flag_attr])*
                        fn $Flag() -> $T { Self::$Flag.bits }
                    )+
                }
                $BitFlags { bits: $(<$BitFlags as __BitFlags>::$Flag())|+ }
            }

            /// Returns the raw value of the flags currently stored.
            #[inline]
            pub fn bits(&self) -> $T {
                self.bits
            }

            /// Convert from underlying bit representation, unless that
            /// representation contains bits that do not correspond to a flag.
            #[inline]
            pub fn from_bits(bits: $T) -> $crate::bitflags::_core::option::Option<$BitFlags> {
                if (bits & !$BitFlags::all().bits()) == 0 {
                    $crate::bitflags::_core::option::Option::Some($BitFlags { bits: bits })
                } else {
                    $crate::bitflags::_core::option::Option::None
                }
            }

            /// Convert from underlying bit representation, dropping any bits
            /// that do not correspond to flags.
            #[inline]
            pub fn from_bits_truncate(bits: $T) -> $BitFlags {
                $BitFlags { bits: bits } & $BitFlags::all()
            }

            /// Returns `true` if no flags are currently stored.
            #[inline]
            pub fn is_empty(&self) -> bool {
                *self == $BitFlags::empty()
            }

            /// Returns `true` if all flags are currently set.
            #[inline]
            pub fn is_all(&self) -> bool {
                *self == $BitFlags::all()
            }

            /// Returns `true` if there are flags common to both `self` and `other`.
            #[inline]
            pub fn intersects(&self, other: $BitFlags) -> bool {
                !(*self & other).is_empty()
            }

            /// Returns `true` all of the flags in `other` are contained within `self`.
            #[inline]
            pub fn contains(&self, other: $BitFlags) -> bool {
                (*self & other) == other
            }

            /// Inserts the specified flags in-place.
            #[inline]
            pub fn insert(&mut self, other: $BitFlags) {
                self.bits |= other.bits;
            }

            /// Removes the specified flags in-place.
            #[inline]
            pub fn remove(&mut self, other: $BitFlags) {
                self.bits &= !other.bits;
            }

            /// Toggles the specified flags in-place.
            #[inline]
            pub fn toggle(&mut self, other: $BitFlags) {
                self.bits ^= other.bits;
            }

            /// Inserts or removes the specified flags depending on the passed value.
            #[inline]
            pub fn set(&mut self, other: $BitFlags, value: bool) {
                if value {
                    self.insert(other);
                } else {
                    self.remove(other);
                }
            }
        }

        impl $crate::bitflags::_core::ops::BitOr for $BitFlags {
            type Output = $BitFlags;

            /// Returns the union of the two sets of flags.
            #[inline]
            fn bitor(self, other: $BitFlags) -> $BitFlags {
                $BitFlags { bits: self.bits | other.bits }
            }
        }

        impl $crate::bitflags::_core::ops::BitOrAssign for $BitFlags {

            /// Adds the set of flags.
            #[inline]
            fn bitor_assign(&mut self, other: $BitFlags) {
                self.bits |= other.bits;
            }
        }

        impl $crate::bitflags::_core::ops::BitXor for $BitFlags {
            type Output = $BitFlags;

            /// Returns the left flags, but with all the right flags toggled.
            #[inline]
            fn bitxor(self, other: $BitFlags) -> $BitFlags {
                $BitFlags { bits: self.bits ^ other.bits }
            }
        }

        impl $crate::bitflags::_core::ops::BitXorAssign for $BitFlags {

            /// Toggles the set of flags.
            #[inline]
            fn bitxor_assign(&mut self, other: $BitFlags) {
                self.bits ^= other.bits;
            }
        }

        impl $crate::bitflags::_core::ops::BitAnd for $BitFlags {
            type Output = $BitFlags;

            /// Returns the intersection between the two sets of flags.
            #[inline]
            fn bitand(self, other: $BitFlags) -> $BitFlags {
                $BitFlags { bits: self.bits & other.bits }
            }
        }

        impl $crate::bitflags::_core::ops::BitAndAssign for $BitFlags {

            /// Disables all flags disabled in the set.
            #[inline]
            fn bitand_assign(&mut self, other: $BitFlags) {
                self.bits &= other.bits;
            }
        }

        impl $crate::bitflags::_core::ops::Sub for $BitFlags {
            type Output = $BitFlags;

            /// Returns the set difference of the two sets of flags.
            #[inline]
            fn sub(self, other: $BitFlags) -> $BitFlags {
                $BitFlags { bits: self.bits & !other.bits }
            }
        }

        impl $crate::bitflags::_core::ops::SubAssign for $BitFlags {

            /// Disables all flags enabled in the set.
            #[inline]
            fn sub_assign(&mut self, other: $BitFlags) {
                self.bits &= !other.bits;
            }
        }

        impl $crate::bitflags::_core::ops::Not for $BitFlags {
            type Output = $BitFlags;

            /// Returns the complement of this set of flags.
            #[inline]
            fn not(self) -> $BitFlags {
                $BitFlags { bits: !self.bits } & $BitFlags::all()
            }
        }

        impl $crate::bitflags::_core::iter::Extend<$BitFlags> for $BitFlags {
            fn extend<T: $crate::bitflags::_core::iter::IntoIterator<Item=$BitFlags>>(&mut self, iterator: T) {
                for item in iterator {
                    self.insert(item)
                }
            }
        }

        impl $crate::bitflags::_core::iter::FromIterator<$BitFlags> for $BitFlags {
            fn from_iter<T: $crate::bitflags::_core::iter::IntoIterator<Item=$BitFlags>>(iterator: T) -> $BitFlags {
                let mut result = Self::empty();
                result.extend(iterator);
                result
            }
        }
    };
}
