#pragma once

#include "rules_structs.h"

#include <string>
#include <vector>
#include <set>
#include <memory>

class DfaBuilderTest;

namespace owlsm
{

// ============================================================================
// AST
// ============================================================================

enum class AstType
{
    LITERAL,
    CHAR_CLASS,
    CONCAT,
    ALTERNATION,
    STAR,
    PLUS,
    OPTIONAL,
};

struct AstNode
{
    AstType type;
    unsigned char literal_char = 0;
    std::vector<bool> char_set = std::vector<bool>(256, false);
    std::vector<std::unique_ptr<AstNode>> children;

    static std::unique_ptr<AstNode> makeLiteral(unsigned char c);
    static std::unique_ptr<AstNode> makeCharClass(const std::vector<bool>& char_set);
    static std::unique_ptr<AstNode> makeUnary(AstType type, std::unique_ptr<AstNode> child);
    static std::unique_ptr<AstNode> makeBinary(AstType type, std::unique_ptr<AstNode> left, std::unique_ptr<AstNode> right);
};

// ============================================================================
// NFA
// ============================================================================

constexpr int EPSILON = -1;

struct NfaState
{
    std::vector<std::pair<int, int>> transitions; // (symbol, target), symbol=-1 for epsilon
};

struct NfaFragment
{
    int start;
    int accept;
};

struct Nfa
{
    std::vector<NfaState> states;
    int start = 0;
    int accept = 0;

    int newState();
    void addTransition(int from, int symbol, int to);
};

// ============================================================================
// Intermediate DFA
// ============================================================================

struct IntermediateDfa
{
    struct State
    {
        int transitions[256];
        bool is_accepting;

        State();
    };

    std::vector<State> states;
    int start = 0;
};

// ============================================================================
// Regex Parser
// ============================================================================

class RegexParser
{
public:
    explicit RegexParser(const std::string& pattern);
    std::unique_ptr<AstNode> parse();

private:
    const std::string& m_pattern;
    size_t m_pos;
    bool m_case_insensitive;

    bool atEnd() const;
    char peek() const;
    char advance();

    std::unique_ptr<AstNode> parseAlternation();
    std::unique_ptr<AstNode> parseConcat();
    std::unique_ptr<AstNode> parseQuantified();
    std::unique_ptr<AstNode> parseBoundedRepetition(std::unique_ptr<AstNode> atom);
    std::unique_ptr<AstNode> cloneNode(const AstNode& node);
    std::unique_ptr<AstNode> expandBoundedRepetition(std::unique_ptr<AstNode> atom, int min_rep, int max_rep);
    std::unique_ptr<AstNode> parseAtom();
    std::unique_ptr<AstNode> parseCharClassAtom();
    std::vector<bool> parseCharClassEscape();
    std::unique_ptr<AstNode> parseEscapeAtom();
    unsigned char resolveEscapeChar(char c) const;
    int parseNumber();

    static std::vector<bool> digitSet();
    static std::vector<bool> wordSet();
    static std::vector<bool> spaceSet();
    static std::vector<bool> dotSet();
    static std::vector<bool> invertSet(const std::vector<bool>& s);
    static void applyCaseInsensitive(std::vector<bool>& s);

    friend class ::DfaBuilderTest;
};

// ============================================================================
// DFA Builder
// ============================================================================

struct RegexDfaResult
{
    flat_2d_dfa_array_t dfa;
    unsigned long long accepting_states;
};

class DfaBuilder
{
public:
    static void buildKmpDfa(const std::string& pattern, flat_2d_dfa_array_t& dfa);
    static RegexDfaResult buildRegexDfa(const std::string& pattern);

private:
    using StateSet = std::set<int>;

    static NfaFragment buildNfaFromAst(Nfa& nfa, const AstNode& node);
    static StateSet epsilonClosure(const Nfa& nfa, const StateSet& states);
    static StateSet nfaMove(const Nfa& nfa, const StateSet& states, int symbol);
    static IntermediateDfa subsetConstruction(const Nfa& nfa);
    static IntermediateDfa minimizeDfa(const IntermediateDfa& dfa);
    static IntermediateDfa normalizeDfa(const IntermediateDfa& dfa);
    static void toFlatDfa(const IntermediateDfa& dfa, flat_2d_dfa_array_t& flat);
    static unsigned long long buildAcceptingStates(const IntermediateDfa& dfa);

    friend class ::DfaBuilderTest;
};

}
