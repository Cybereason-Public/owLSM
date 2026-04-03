#include "dfa_builder.hpp"

#include <queue>
#include <map>
#include <stdexcept>
#include <algorithm>
#include <cstring>

namespace owlsm
{

// ============================================================================
// AstNode
// ============================================================================

std::unique_ptr<AstNode> AstNode::makeLiteral(unsigned char c)
{
    auto node = std::make_unique<AstNode>();
    node->type = AstType::LITERAL;
    node->literal_char = c;
    return node;
}

std::unique_ptr<AstNode> AstNode::makeCharClass(const std::vector<bool>& char_set)
{
    auto node = std::make_unique<AstNode>();
    node->type = AstType::CHAR_CLASS;
    node->char_set = char_set;
    return node;
}

std::unique_ptr<AstNode> AstNode::makeUnary(AstType type, std::unique_ptr<AstNode> child)
{
    auto node = std::make_unique<AstNode>();
    node->type = type;
    node->children.push_back(std::move(child));
    return node;
}

std::unique_ptr<AstNode> AstNode::makeBinary(AstType type, std::unique_ptr<AstNode> left, std::unique_ptr<AstNode> right)
{
    auto node = std::make_unique<AstNode>();
    node->type = type;
    node->children.push_back(std::move(left));
    node->children.push_back(std::move(right));
    return node;
}

// ============================================================================
// Nfa
// ============================================================================

int Nfa::newState()
{
    states.emplace_back();
    return static_cast<int>(states.size() - 1);
}

void Nfa::addTransition(int from, int symbol, int to)
{
    states[from].transitions.push_back({symbol, to});
}

// ============================================================================
// IntermediateDfa::State
// ============================================================================

IntermediateDfa::State::State()
{
    std::fill(std::begin(transitions), std::end(transitions), -1);
    is_accepting = false;
}

// ============================================================================
// RegexParser - character set helpers
// ============================================================================

std::vector<bool> RegexParser::digitSet()
{
    std::vector<bool> s(256, false);
    for (int c = '0'; c <= '9'; ++c)
    {
        s[c] = true;
    }
    return s;
}

std::vector<bool> RegexParser::wordSet()
{
    std::vector<bool> s(256, false);
    for (int c = 'a'; c <= 'z'; ++c)
    {
        s[c] = true;
    }
    for (int c = 'A'; c <= 'Z'; ++c)
    {
        s[c] = true;
    }
    for (int c = '0'; c <= '9'; ++c)
    {
        s[c] = true;
    }
    s['_'] = true;
    return s;
}

std::vector<bool> RegexParser::spaceSet()
{
    std::vector<bool> s(256, false);
    s[' '] = true;
    s['\t'] = true;
    s['\n'] = true;
    s['\r'] = true;
    s['\f'] = true;
    s['\v'] = true;
    return s;
}

std::vector<bool> RegexParser::dotSet()
{
    std::vector<bool> s(256, false);
    for (int c = 32; c <= 126; ++c)
    {
        s[c] = true;
    }
    return s;
}

std::vector<bool> RegexParser::invertSet(const std::vector<bool>& s)
{
    std::vector<bool> result(256, false);
    for (int c = 0; c < 256; ++c)
    {
        result[c] = !s[c];
    }
    return result;
}

void RegexParser::applyCaseInsensitive(std::vector<bool>& s)
{
    for (int c = 'a'; c <= 'z'; ++c)
    {
        if (s[c] || s[c - 32])
        {
            s[c] = true;
            s[c - 32] = true;
        }
    }
}

// ============================================================================
// RegexParser - core
// ============================================================================

RegexParser::RegexParser(const std::string& pattern)
    : m_pattern(pattern), m_pos(0), m_case_insensitive(false)
{
}

bool RegexParser::atEnd() const { return m_pos >= m_pattern.size(); }
char RegexParser::peek() const { return m_pattern[m_pos]; }
char RegexParser::advance() { return m_pattern[m_pos++]; }

std::unique_ptr<AstNode> RegexParser::parse()
{
    if (m_pattern.size() >= 4 && m_pattern.substr(0, 4) == "(?i)")
    {
        m_case_insensitive = true;
        m_pos = 4;
    }

    auto result = parseAlternation();
    if (m_pos != m_pattern.size())
    {
        throw std::runtime_error("Unexpected character at position " + std::to_string(m_pos) + " in regex: " + m_pattern);
    }
    return result;
}

std::unique_ptr<AstNode> RegexParser::parseAlternation()
{
    auto left = parseConcat();
    while (!atEnd() && peek() == '|')
    {
        advance();
        auto right = parseConcat();
        left = AstNode::makeBinary(AstType::ALTERNATION, std::move(left), std::move(right));
    }
    return left;
}

std::unique_ptr<AstNode> RegexParser::parseConcat()
{
    std::unique_ptr<AstNode> result = nullptr;

    while (!atEnd() && peek() != '|' && peek() != ')')
    {
        auto atom = parseQuantified();
        if (!result)
        {
            result = std::move(atom);
        }
        else
        {
            result = AstNode::makeBinary(AstType::CONCAT, std::move(result), std::move(atom));
        }
    }

    if (!result)
    {
        throw std::runtime_error("Empty expression in regex: " + m_pattern);
    }
    return result;
}

std::unique_ptr<AstNode> RegexParser::parseQuantified()
{
    auto atom = parseAtom();

    if (atEnd())
    {
        return atom;
    }

    char c = peek();
    if (c == '*')
    {
        advance();
        if (!atEnd() && peek() == '?')
        {
            advance();
        }
        return AstNode::makeUnary(AstType::STAR, std::move(atom));
    }
    if (c == '+')
    {
        advance();
        if (!atEnd() && peek() == '?')
        {
            advance();
        }
        return AstNode::makeUnary(AstType::PLUS, std::move(atom));
    }
    if (c == '?')
    {
        advance();
        if (!atEnd() && peek() == '?')
        {
            advance();
        }
        return AstNode::makeUnary(AstType::OPTIONAL, std::move(atom));
    }
    if (c == '{')
    {
        return parseBoundedRepetition(std::move(atom));
    }

    return atom;
}

std::unique_ptr<AstNode> RegexParser::parseBoundedRepetition(std::unique_ptr<AstNode> atom)
{
    advance(); // consume '{'
    int min_rep = parseNumber();
    int max_rep = min_rep;

    if (!atEnd() && peek() == ',')
    {
        advance();
        if (!atEnd() && peek() != '}')
        {
            max_rep = parseNumber();
        }
        else
        {
            max_rep = -1; // unbounded
        }
    }

    if (atEnd() || peek() != '}')
    {
        throw std::runtime_error("Expected '}' in bounded repetition in regex: " + m_pattern);
    }
    advance(); // consume '}'

    if (!atEnd() && peek() == '?')
    {
        advance();
    }

    if (min_rep < 0 || (max_rep != -1 && max_rep < min_rep))
    {
        throw std::runtime_error("Invalid repetition bounds in regex: " + m_pattern);
    }

    return expandBoundedRepetition(std::move(atom), min_rep, max_rep);
}

std::unique_ptr<AstNode> RegexParser::cloneNode(const AstNode& node)
{
    auto copy = std::make_unique<AstNode>();
    copy->type = node.type;
    copy->literal_char = node.literal_char;
    copy->char_set = node.char_set;
    for (const auto& child : node.children)
    {
        copy->children.push_back(cloneNode(*child));
    }
    return copy;
}

std::unique_ptr<AstNode> RegexParser::expandBoundedRepetition(std::unique_ptr<AstNode> atom, int min_rep, int max_rep)
{
    if (min_rep == 0 && max_rep == 0)
    {
        throw std::runtime_error("Repetition {0} is not supported in regex: " + m_pattern);
    }

    // {n}: exactly n times
    // {n,}: at least n times = n copies + star
    // {n,m}: between n and m times = n copies + (m-n) optional copies

    std::unique_ptr<AstNode> result = nullptr;

    for (int i = 0; i < min_rep; ++i)
    {
        if (i == 0)
        {
            if (min_rep == 1 && max_rep == 1)
            {
                return atom;
            }
            auto saved = cloneNode(*atom);
            result = std::move(atom);
            atom = std::move(saved);
        }
        else
        {
            auto copy = cloneNode(*atom);
            result = AstNode::makeBinary(AstType::CONCAT, std::move(result), std::move(copy));
        }
    }

    if (max_rep == -1)
    {
        auto star_copy = cloneNode(*atom);
        auto star_node = AstNode::makeUnary(AstType::STAR, std::move(star_copy));
        if (result)
        {
            result = AstNode::makeBinary(AstType::CONCAT, std::move(result), std::move(star_node));
        }
        else
        {
            result = std::move(star_node);
        }
    }
    else if (max_rep > min_rep)
    {
        for (int i = 0; i < max_rep - min_rep; ++i)
        {
            auto opt_copy = cloneNode(*atom);
            auto opt_node = AstNode::makeUnary(AstType::OPTIONAL, std::move(opt_copy));
            if (result)
            {
                result = AstNode::makeBinary(AstType::CONCAT, std::move(result), std::move(opt_node));
            }
            else
            {
                result = std::move(opt_node);
            }
        }
    }

    if (!result)
    {
        throw std::runtime_error("Failed to expand bounded repetition in regex: " + m_pattern);
    }
    return result;
}

std::unique_ptr<AstNode> RegexParser::parseAtom()
{
    if (atEnd())
    {
        throw std::runtime_error("Unexpected end of regex: " + m_pattern);
    }

    char c = peek();

    if (c == '(')
    {
        advance();
        auto inner = parseAlternation();
        if (atEnd() || peek() != ')')
        {
            throw std::runtime_error("Unmatched '(' in regex: " + m_pattern);
        }
        advance();
        return inner;
    }

    if (c == '[')
    {
        return parseCharClassAtom();
    }

    if (c == '.')
    {
        advance();
        auto s = dotSet();
        if (m_case_insensitive)
        {
            applyCaseInsensitive(s);
        }
        return AstNode::makeCharClass(s);
    }

    if (c == '\\')
    {
        return parseEscapeAtom();
    }

    advance();
    if (m_case_insensitive && std::isalpha(static_cast<unsigned char>(c)))
    {
        std::vector<bool> s(256, false);
        s[static_cast<unsigned char>(std::tolower(static_cast<unsigned char>(c)))] = true;
        s[static_cast<unsigned char>(std::toupper(static_cast<unsigned char>(c)))] = true;
        return AstNode::makeCharClass(s);
    }
    return AstNode::makeLiteral(static_cast<unsigned char>(c));
}

std::unique_ptr<AstNode> RegexParser::parseCharClassAtom()
{
    advance(); // consume '['
    bool negated = false;
    if (!atEnd() && peek() == '^')
    {
        negated = true;
        advance();
    }

    std::vector<bool> s(256, false);
    bool first = true;

    while (!atEnd() && (peek() != ']' || first))
    {
        first = false;
        if (peek() == '\\')
        {
            advance();
            auto escape_set = parseCharClassEscape();
            for (int i = 0; i < 256; ++i)
            {
                if (escape_set[i])
                {
                    s[i] = true;
                }
            }
        }
        else
        {
            unsigned char start = static_cast<unsigned char>(advance());
            if (!atEnd() && peek() == '-' && m_pos + 1 < m_pattern.size() && m_pattern[m_pos + 1] != ']')
            {
                advance(); // consume '-'
                unsigned char end = static_cast<unsigned char>(advance());
                if (end < start)
                {
                    throw std::runtime_error("Invalid character range in regex: " + m_pattern);
                }
                for (int c2 = start; c2 <= end; ++c2)
                {
                    s[c2] = true;
                }
            }
            else
            {
                s[start] = true;
            }
        }
    }

    if (atEnd())
    {
        throw std::runtime_error("Unmatched '[' in regex: " + m_pattern);
    }
    advance(); // consume ']'

    if (negated)
    {
        s = invertSet(s);
    }

    if (m_case_insensitive)
    {
        applyCaseInsensitive(s);
    }

    return AstNode::makeCharClass(s);
}

std::vector<bool> RegexParser::parseCharClassEscape()
{
    if (atEnd())
    {
        throw std::runtime_error("Unexpected end of escape in regex: " + m_pattern);
    }
    char c = advance();
    switch (c)
    {
        case 'd': return digitSet();
        case 'D': return invertSet(digitSet());
        case 'w': return wordSet();
        case 'W': return invertSet(wordSet());
        case 's': return spaceSet();
        case 'S': return invertSet(spaceSet());
        default:
        {
            std::vector<bool> s(256, false);
            s[static_cast<unsigned char>(resolveEscapeChar(c))] = true;
            return s;
        }
    }
}

std::unique_ptr<AstNode> RegexParser::parseEscapeAtom()
{
    advance(); // consume '\'
    if (atEnd())
    {
        throw std::runtime_error("Unexpected end of escape sequence in regex: " + m_pattern);
    }
    char c = peek();

    if (c == 'd' || c == 'D' || c == 'w' || c == 'W' || c == 's' || c == 'S')
    {
        advance();
        std::vector<bool> s;
        switch (c)
        {
            case 'd': s = digitSet(); break;
            case 'D': s = invertSet(digitSet()); break;
            case 'w': s = wordSet(); break;
            case 'W': s = invertSet(wordSet()); break;
            case 's': s = spaceSet(); break;
            case 'S': s = invertSet(spaceSet()); break;
        }
        if (m_case_insensitive)
        {
            applyCaseInsensitive(s);
        }
        return AstNode::makeCharClass(s);
    }

    advance();
    unsigned char resolved = resolveEscapeChar(c);
    if (m_case_insensitive && std::isalpha(resolved))
    {
        std::vector<bool> s(256, false);
        s[static_cast<unsigned char>(std::tolower(resolved))] = true;
        s[static_cast<unsigned char>(std::toupper(resolved))] = true;
        return AstNode::makeCharClass(s);
    }
    return AstNode::makeLiteral(resolved);
}

unsigned char RegexParser::resolveEscapeChar(char c) const
{
    switch (c)
    {
        case 'n': return '\n';
        case 't': return '\t';
        case 'r': return '\r';
        case 'f': return '\f';
        case 'v': return '\v';
        case 'a': return '\a';
        case '0': return '\0';
        default:  return static_cast<unsigned char>(c);
    }
}

int RegexParser::parseNumber()
{
    if (atEnd() || !std::isdigit(static_cast<unsigned char>(peek())))
    {
        throw std::runtime_error("Expected number in regex: " + m_pattern);
    }
    int num = 0;
    while (!atEnd() && std::isdigit(static_cast<unsigned char>(peek())))
    {
        num = num * 10 + (advance() - '0');
    }
    return num;
}

// ============================================================================
// DfaBuilder - NFA construction (Thompson's)
// ============================================================================

NfaFragment DfaBuilder::buildNfaFromAst(Nfa& nfa, const AstNode& node)
{
    switch (node.type)
    {
        case AstType::LITERAL:
        {
            int s = nfa.newState();
            int a = nfa.newState();
            nfa.addTransition(s, node.literal_char, a);
            return {s, a};
        }

        case AstType::CHAR_CLASS:
        {
            int s = nfa.newState();
            int a = nfa.newState();
            for (int c = 0; c < 256; ++c)
            {
                if (node.char_set[c])
                {
                    nfa.addTransition(s, c, a);
                }
            }
            return {s, a};
        }

        case AstType::CONCAT:
        {
            auto left = buildNfaFromAst(nfa, *node.children[0]);
            auto right = buildNfaFromAst(nfa, *node.children[1]);
            nfa.addTransition(left.accept, EPSILON, right.start);
            return {left.start, right.accept};
        }

        case AstType::ALTERNATION:
        {
            int s = nfa.newState();
            int a = nfa.newState();
            auto left = buildNfaFromAst(nfa, *node.children[0]);
            auto right = buildNfaFromAst(nfa, *node.children[1]);
            nfa.addTransition(s, EPSILON, left.start);
            nfa.addTransition(s, EPSILON, right.start);
            nfa.addTransition(left.accept, EPSILON, a);
            nfa.addTransition(right.accept, EPSILON, a);
            return {s, a};
        }

        case AstType::STAR:
        {
            int s = nfa.newState();
            int a = nfa.newState();
            auto inner = buildNfaFromAst(nfa, *node.children[0]);
            nfa.addTransition(s, EPSILON, inner.start);
            nfa.addTransition(s, EPSILON, a);
            nfa.addTransition(inner.accept, EPSILON, inner.start);
            nfa.addTransition(inner.accept, EPSILON, a);
            return {s, a};
        }

        case AstType::PLUS:
        {
            int s = nfa.newState();
            int a = nfa.newState();
            auto inner = buildNfaFromAst(nfa, *node.children[0]);
            nfa.addTransition(s, EPSILON, inner.start);
            nfa.addTransition(inner.accept, EPSILON, inner.start);
            nfa.addTransition(inner.accept, EPSILON, a);
            return {s, a};
        }

        case AstType::OPTIONAL:
        {
            int s = nfa.newState();
            int a = nfa.newState();
            auto inner = buildNfaFromAst(nfa, *node.children[0]);
            nfa.addTransition(s, EPSILON, inner.start);
            nfa.addTransition(s, EPSILON, a);
            nfa.addTransition(inner.accept, EPSILON, a);
            return {s, a};
        }
    }

    throw std::runtime_error("Unknown AST node type");
}

// ============================================================================
// DfaBuilder - subset construction (NFA → DFA)
// ============================================================================

DfaBuilder::StateSet DfaBuilder::epsilonClosure(const Nfa& nfa, const StateSet& states)
{
    StateSet closure = states;
    std::queue<int> work;
    for (int s : states)
    {
        work.push(s);
    }

    while (!work.empty())
    {
        int current = work.front();
        work.pop();

        for (const auto& [symbol, target] : nfa.states[current].transitions)
        {
            if (symbol == EPSILON && closure.find(target) == closure.end())
            {
                closure.insert(target);
                work.push(target);
            }
        }
    }
    return closure;
}

DfaBuilder::StateSet DfaBuilder::nfaMove(const Nfa& nfa, const StateSet& states, int symbol)
{
    StateSet result;
    for (int s : states)
    {
        for (const auto& [sym, target] : nfa.states[s].transitions)
        {
            if (sym == symbol)
            {
                result.insert(target);
            }
        }
    }
    return result;
}

IntermediateDfa DfaBuilder::subsetConstruction(const Nfa& nfa)
{
    IntermediateDfa dfa;

    std::map<StateSet, int> state_map;
    std::queue<StateSet> work;

    StateSet start_set = epsilonClosure(nfa, {nfa.start});
    state_map[start_set] = 0;
    dfa.states.emplace_back();
    dfa.states[0].is_accepting = (start_set.count(nfa.accept) > 0);
    dfa.start = 0;
    work.push(start_set);

    while (!work.empty())
    {
        StateSet current = work.front();
        work.pop();
        int current_id = state_map[current];

        for (int c = 0; c < 256; ++c)
        {
            StateSet moved = nfaMove(nfa, current, c);
            if (moved.empty())
            {
                continue;
            }

            StateSet target = epsilonClosure(nfa, moved);
            if (target.empty())
            {
                continue;
            }

            auto it = state_map.find(target);
            if (it == state_map.end())
            {
                int new_id = static_cast<int>(dfa.states.size());
                if (new_id >= MAX_REGEX_DFA_STATES)
                {
                    throw std::runtime_error("Regex produces too many DFA states (>" + std::to_string(MAX_REGEX_DFA_STATES) + "). Simplify the pattern.");
                }
                state_map[target] = new_id;
                dfa.states.emplace_back();
                dfa.states[new_id].is_accepting = (target.count(nfa.accept) > 0);
                work.push(target);
                dfa.states[current_id].transitions[c] = new_id;
            }
            else
            {
                dfa.states[current_id].transitions[c] = it->second;
            }
        }
    }

    return dfa;
}

// ============================================================================
// DfaBuilder - minimization (partition refinement)
// ============================================================================

IntermediateDfa DfaBuilder::minimizeDfa(const IntermediateDfa& dfa)
{
    const int n = static_cast<int>(dfa.states.size());
    if (n <= 1)
    {
        return dfa;
    }

    IntermediateDfa complete;
    const int dead_id = n;
    complete.states.resize(n + 1);
    complete.start = dfa.start;

    for (int i = 0; i < n; ++i)
    {
        complete.states[i].is_accepting = dfa.states[i].is_accepting;
        for (int c = 0; c < 256; ++c)
        {
            int target = dfa.states[i].transitions[c];
            complete.states[i].transitions[c] = (target == -1) ? dead_id : target;
        }
    }
    complete.states[dead_id].is_accepting = false;
    for (int c = 0; c < 256; ++c)
    {
        complete.states[dead_id].transitions[c] = dead_id;
    }

    const int total = n + 1;

    std::vector<int> partition(total, 0);
    int num_groups = 1;

    bool has_accepting = false;
    bool has_non_accepting = false;
    for (int i = 0; i < total; ++i)
    {
        if (complete.states[i].is_accepting)
        {
            has_accepting = true;
        }
        else
        {
            has_non_accepting = true;
        }
    }

    if (has_accepting && has_non_accepting)
    {
        num_groups = 2;
        for (int i = 0; i < total; ++i)
        {
            partition[i] = complete.states[i].is_accepting ? 1 : 0;
        }
    }

    bool changed = true;
    while (changed)
    {
        changed = false;

        std::vector<int> new_partition(total);
        int new_num_groups = 0;
        std::map<std::pair<int, std::vector<int>>, int> signature_map;

        for (int i = 0; i < total; ++i)
        {
            std::vector<int> sig(256);
            for (int c = 0; c < 256; ++c)
            {
                sig[c] = partition[complete.states[i].transitions[c]];
            }

            auto key = std::make_pair(partition[i], sig);
            auto it = signature_map.find(key);
            if (it == signature_map.end())
            {
                int gid = new_num_groups++;
                signature_map[key] = gid;
                new_partition[i] = gid;
            }
            else
            {
                new_partition[i] = it->second;
            }
        }

        if (new_num_groups > num_groups)
        {
            changed = true;
            partition = new_partition;
            num_groups = new_num_groups;
        }
    }

    IntermediateDfa minimized;
    minimized.states.resize(num_groups);
    minimized.start = partition[complete.start];

    std::vector<bool> group_filled(num_groups, false);
    for (int i = 0; i < total; ++i)
    {
        int g = partition[i];
        if (!group_filled[g])
        {
            group_filled[g] = true;
            minimized.states[g].is_accepting = complete.states[i].is_accepting;
            for (int c = 0; c < 256; ++c)
            {
                minimized.states[g].transitions[c] = partition[complete.states[i].transitions[c]];
            }
        }
    }

    return minimized;
}

// ============================================================================
// DfaBuilder - normalization (dead=0, start=1)
// ============================================================================

IntermediateDfa DfaBuilder::normalizeDfa(const IntermediateDfa& dfa)
{
    const int n = static_cast<int>(dfa.states.size());

    int dead_state = -1;
    for (int i = 0; i < n; ++i)
    {
        if (dfa.states[i].is_accepting)
        {
            continue;
        }
        bool all_self = true;
        for (int c = 0; c < 256; ++c)
        {
            if (dfa.states[i].transitions[c] != i)
            {
                all_self = false;
                break;
            }
        }
        if (all_self)
        {
            dead_state = i;
            break;
        }
    }

    std::vector<int> remap(n, -1);
    int next_id = 0;

    if (dead_state >= 0)
    {
        remap[dead_state] = next_id++;
    }
    else
    {
        next_id++;
    }

    remap[dfa.start] = next_id++;

    for (int i = 0; i < n; ++i)
    {
        if (remap[i] == -1)
        {
            remap[i] = next_id++;
        }
    }

    int total_states = (dead_state >= 0) ? n : n + 1;

    if (total_states > MAX_REGEX_DFA_STATES)
    {
        throw std::runtime_error("Regex DFA exceeds maximum state count (" + std::to_string(MAX_REGEX_DFA_STATES) + ") after normalization.");
    }

    IntermediateDfa normalized;
    normalized.states.resize(total_states);
    normalized.start = 1;

    normalized.states[0].is_accepting = false;
    for (int c = 0; c < 256; ++c)
    {
        normalized.states[0].transitions[c] = 0;
    }

    for (int i = 0; i < n; ++i)
    {
        int new_id = remap[i];
        normalized.states[new_id].is_accepting = dfa.states[i].is_accepting;
        for (int c = 0; c < 256; ++c)
        {
            int target = dfa.states[i].transitions[c];
            if (target == -1)
            {
                normalized.states[new_id].transitions[c] = 0;
            }
            else
            {
                normalized.states[new_id].transitions[c] = remap[target];
            }
        }
    }

    return normalized;
}

// ============================================================================
// DfaBuilder - conversion to flat representation
// ============================================================================

void DfaBuilder::toFlatDfa(const IntermediateDfa& dfa, flat_2d_dfa_array_t& flat)
{
    std::memset(&flat, 0, sizeof(flat_2d_dfa_array_t));

    for (int state = 0; state < static_cast<int>(dfa.states.size()); ++state)
    {
        for (int c = 0; c < 256; ++c)
        {
            size_t idx = (state * DFA_ALPHABET_SIZE) + c;
            int target = dfa.states[state].transitions[c];
            flat.value[idx] = static_cast<unsigned char>(target >= 0 ? target : 0);
        }
    }
}

unsigned long long DfaBuilder::buildAcceptingStates(const IntermediateDfa& dfa)
{
    unsigned long long result = 0;

    for (int i = 0; i < static_cast<int>(dfa.states.size()); ++i)
    {
        if (dfa.states[i].is_accepting)
        {
            result |= (1ULL << i);
        }
    }

    return result;
}

// ============================================================================
// DfaBuilder - public API
// ============================================================================

void DfaBuilder::buildKmpDfa(const std::string& pattern, flat_2d_dfa_array_t& dfa)
{
    std::memset(&dfa, 0, sizeof(flat_2d_dfa_array_t));

    size_t pattern_len = pattern.length();

    std::vector<int> failure(pattern_len, 0);
    int k = 0;
    for (size_t i = 1; i < pattern_len; ++i)
    {
        while (k > 0 && pattern[k] != pattern[i])
        {
            k = failure[k - 1];
        }
        if (pattern[k] == pattern[i])
        {
            ++k;
        }
        failure[i] = k;
    }

    for (size_t state = 0; state <= pattern_len; ++state)
    {
        for (int c = 0; c < 256; ++c)
        {
            size_t idx = (state * DFA_ALPHABET_SIZE) + c;

            if (state < pattern_len && static_cast<unsigned char>(pattern[state]) == c)
            {
                dfa.value[idx] = static_cast<unsigned char>(state + 1);
            }
            else if (state == 0)
            {
                dfa.value[idx] = 0;
            }
            else
            {
                size_t fail_idx = (failure[state - 1] * DFA_ALPHABET_SIZE) + c;
                dfa.value[idx] = dfa.value[fail_idx];
            }
        }
    }
}

RegexDfaResult DfaBuilder::buildRegexDfa(const std::string& pattern)
{
    if (pattern.empty())
    {
        throw std::runtime_error("Empty regex pattern");
    }

    RegexParser parser(pattern);
    auto ast = parser.parse();

    Nfa nfa;
    auto fragment = buildNfaFromAst(nfa, *ast);

    // Unanchored matching: add a skip state that self-loops on all 256 byte values
    // and has an epsilon transition to the pattern start.
    int skip_state = nfa.newState();
    for (int c = 0; c < 256; ++c)
    {
        nfa.addTransition(skip_state, c, skip_state);
    }
    nfa.addTransition(skip_state, EPSILON, fragment.start);

    nfa.start = skip_state;
    nfa.accept = fragment.accept;

    auto dfa = subsetConstruction(nfa);
    dfa = minimizeDfa(dfa);
    dfa = normalizeDfa(dfa);

    bool has_accepting = false;
    for (const auto& state : dfa.states)
    {
        if (state.is_accepting)
        {
            has_accepting = true;
            break;
        }
    }
    if (!has_accepting)
    {
        throw std::runtime_error("Regex DFA has no accepting states. Pattern can never match.");
    }

    RegexDfaResult result;
    toFlatDfa(dfa, result.dfa);
    result.accepting_states = buildAcceptingStates(dfa);

    return result;
}

}
