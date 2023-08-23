// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMMON_ARGSREGISTER_H
#define BITCOIN_COMMON_ARGSREGISTER_H

#include <common/args.h>

#include <type_traits>

/** Typesafe args registration.  */

/** Example usage:

constexpr bool DEFAULT_FOO_A{true};

struct FooOpts {
    bool a{DEFAULT_FOO_A};
    std::optional<std::string> b;
    std::vector<std::string> c;
    Custom d;
};

class FooRegister
{
public:
    using T = CChainParams::SigNetOptions;

    static inline void GetD(Custom& d, const std::string& arg_d);

    template<typename C, typename Op>
    static inline void Register(Op& op)
    {
        return C::Do(op,
            C::Defn(&T::a, "-fooa", "",
                    "Description of option A",
                    ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION,
                    OptionsCategory::DEBUG_TEST),
            C::Defn(&T::b, "-foob", "=bar",
                    "Description of option B",
                    ArgsManager::ALLOW_ANY,
                    OptionsCategory::DEBUG_TEST),
            C::Defn(&T::c, "-foob", "=bar",
                    "Description of option B",
                    ArgsManager::ALLOW_ANY,
                    OptionsCategory::DEBUG_TEST),
            C::Defn(&T::d, "-foob", "=bar", GetD,
                    "Description of option B",
                    ArgsManager::ALLOW_ANY,
                    OptionsCategory::DEBUG_TEST)
            );
    }
};

void SetupFooOptions(ArgsManager& argsman)
{
    ArgsRegister<FooArgsRegister>::Register(argsman);
}

void ReadFooArgs(const ArgsManager& args, FooOpts& options)
{
    ArgsRegister<FooArgsRegister>::Update(args, options);
}

**/

template<typename REG>
class ArgsRegister
{
public:
    using STRUCT = typename REG::T;

    static inline void Register(ArgsManager& args)
    {
        auto l = [&](const auto& sd) {
            using AT = typename std::remove_reference_t<decltype(sd)>::ArgType;
            args.AddTypedArg<AT>(sd.name+sd.params, sd.desc, sd.flags, sd.cat);
        };
        (REG::template Register<_Do>)(l);
    }

    static inline void Update(const ArgsManager& args, STRUCT& options)
    {
        auto l = [&](const auto& sd) {
            using AT = typename std::remove_reference_t<decltype(sd)>::ArgType;
            auto arg = args.Get<AT>(sd.name);
            if (arg.has_value()) {
                sd.cvt(options.*(sd.field), arg.value());
            }
        };
        (REG::template Register<_Do>)(l);
    }

private:
    template<typename FT, typename AT=FT>
    struct ArgDefn
    {
        using FieldType = FT;
        using ArgType = AT;

        void (&cvt)(FieldType&, const ArgType&);
        FieldType STRUCT::* field;
        std::string name;
        std::string params; // "=blah" or ""
        std::string desc;
        unsigned int flags;
        OptionsCategory cat;
    };

    class _Do
    {
    private:
        template<typename Op>
        static inline void Do(Op& op) { }

        template<typename T>
        static inline void set_directly(T& dst, const T& src) { dst = src; }

        template<typename T>
        static inline void set_optional(std::optional<T>& dst, const T& src) { dst = src; }

    public:
        template<typename T, typename... Ts>
        static inline ArgDefn<std::optional<T>, T> Defn(std::optional<T> STRUCT::* field, const std::string& name, const std::string& params, const std::string& desc, Ts... ts)
        {
            return { set_optional<T>, field, name, params, desc, ts... };
        }

        template<typename T, typename... Ts>
        static inline ArgDefn<T> Defn(T STRUCT::* field, const std::string& name, const std::string& params, const std::string& desc, Ts... ts)
        {
            return { set_directly<T>, field, name, params, desc, ts... };
        }

        template<typename FT, typename AT, typename... Ts>
        static inline ArgDefn<FT,AT> Defn(FT STRUCT::* field, const std::string& name, const std::string& params, void(&cvt)(FT&,const AT&), const std::string& desc, Ts... ts)
        {
            return { cvt, field, name, params, desc, ts... };
        }

        template<typename Op, typename FT, typename AT, typename... Ts>
        static inline void Do(Op& op, const ArgDefn<FT, AT>& sd, Ts... ts)
        {
            op(sd);
            Do(op, ts...);
        }
    };
};

#endif // BITCOIN_COMMON_ARGSREGISTER_H
