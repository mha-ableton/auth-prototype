#include <chrono>
#include <random>
#include <string>
#include <vector>

#include "httplib.h"
#include "json.hpp"
#include "picosha2.h"

constexpr auto DIGIT_ALPHABET = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
constexpr auto HEX_ALPHABET = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

constexpr auto CODE_STR_LEN = 6;
constexpr auto CHALLENGE_STR_LEN = 8;
constexpr auto CHALLENGE_MAX_AGE_IN_SECONDS = 60;
constexpr auto SESSION_MAX_AGE_IN_SECONDS = 60 * 60 * 24 * 7;
constexpr auto AUTH_HEADER_NAME = "X-My-Auth-Header";

struct Challenge
{
    std::string code; // the code that was valid at the moment the challenge was generated
    std::string challenge;
    std::chrono::system_clock::time_point created_at;
};

struct Session
{
    std::string token;
    std::chrono::system_clock::time_point created_at;
};

class Api
{
public:
    Api()
        : m_current_code(generate_random_string(CODE_STR_LEN, DIGIT_ALPHABET))
    {
        std::cout << "Current access code is " << m_current_code << std::endl;
    }

    // TODO add rate limiting
    void onChallenge(const httplib::Request &req, httplib::Response &res)
    {
        Challenge challenge;
        challenge.code = m_current_code;
        challenge.challenge = generate_random_string(CHALLENGE_STR_LEN, HEX_ALPHABET);
        challenge.created_at = std::chrono::system_clock::now();
        m_challenges.push_back(challenge);

        nlohmann::json body;
        body["challenge"] = challenge.challenge;
        return_json(res, body);
    }

    // TODO add rate limiting
    void onLogin(const httplib::Request &req, httplib::Response &res)
    {
        nlohmann::json reqBody;
        std::stringstream(req.body) >> reqBody;

        auto responseStr = reqBody["response"].get<std::string>();
        if (responseStr.empty())
        {
            res.status = 401;
            return;
        }

        std::string challenge, response;
        if (!parse_challenge_response(responseStr, challenge, response))
        {
            res.status = 401;
            return;
        }

        Challenge c;
        if (!find_challenge(c, challenge))
        {
            res.status = 401;
            return;
        }

        if (!is_valid_response(c, response))
        {
            res.status = 401;
            return;
        }

        Session s;
        s.created_at = std::chrono::system_clock::now();
        s.token = generate_random_string(64, HEX_ALPHABET);
        m_sessions.push_back(s);

        nlohmann::json body;
        body["token"] = s.token;
        return_json(res, body);
    }

    void onSecret(const httplib::Request &req, httplib::Response &res)
    {
        if (!req.has_header(AUTH_HEADER_NAME))
        {
            res.status = 401;
            return;
        }

        auto token = req.get_header_value(AUTH_HEADER_NAME);
        if (token.empty())
        {
            res.status = 401;
            return;
        }

        remove_expired_sessions();

        if (!is_valid_session_token(token))
        {
            res.status = 401;
            return;
        }

        nlohmann::json body;
        body["secret"] = 42;
        return_json(res, body);
    }

private:
    std::string generate_random_string(int len, const std::vector<char> &alphabet)
    {
        std::random_device rd;
        std::mt19937 rng(rd());
        std::uniform_int_distribution<int> uni(0, alphabet.size() - 1);

        std::string res = "";
        for (int i = 0; i < len; ++i)
        {
            res += alphabet[uni(rng)];
        }
        return res;
    }

    bool parse_challenge_response(const std::string &str, std::string &challenge, std::string &response)
    {
        auto idx = str.find('-');
        if (idx == std::string::npos)
        {
            return false;
        }
        challenge = str.substr(0, idx);
        response = str.substr(idx + 1);
        if (challenge.empty() || response.empty())
        {
            return false;
        }

        to_lower(challenge);
        to_lower(response);

        if (!is_hex_string(challenge) || !is_hex_string(response))
        {
            return false;
        }

        return true;
    }

    bool find_challenge(Challenge &challenge, const std::string &str)
    {
        remove_expired_challenges();

        // TODO protect m_challenges with mutex
        auto it = std::find_if(m_challenges.begin(), m_challenges.end(),
                               [&str](const auto &entry) { return entry.challenge == str; });
        if (it == m_challenges.end())
        {
            return false;
        }

        challenge = *it;
        m_challenges.erase(it);
        return true;
    }

    void remove_expired_challenges()
    {
        auto now = std::chrono::system_clock::now();
        // TODO protect m_challenges with mutex
        std::remove_if(m_challenges.begin(), m_challenges.end(), [now](const auto &entry) -> bool {
            auto duration = now - entry.created_at;
            auto diff = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
            return diff > CHALLENGE_MAX_AGE_IN_SECONDS;
        });
    }

    bool is_valid_response(const Challenge &c, const std::string &actual)
    {
        const auto str = c.challenge + "-" + c.code;
        auto expected = picosha2::hash256_hex_string(str);
        to_lower(expected);
        return expected == actual;
    }

    void remove_expired_sessions()
    {
        auto now = std::chrono::system_clock::now();
        // TODO protect m_challenges with mutex
        std::remove_if(m_sessions.begin(), m_sessions.end(), [now](const auto &entry) -> bool {
            auto duration = now - entry.created_at;
            auto diff = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
            return diff > SESSION_MAX_AGE_IN_SECONDS;
        });
    }

    bool is_valid_session_token(const std::string &token)
    {
        auto it = std::find_if(m_sessions.begin(), m_sessions.end(), [&token](const auto &entry) { return entry.token == token; });
        return it != m_sessions.end();
    }

    void to_lower(std::string &str)
    {
        std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) { return std::tolower(c); });
    }

    bool is_hex_string(const std::string &str)
    {
        return str.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos;
    }

    void return_json(httplib::Response &res, const nlohmann::json &body)
    {
        std::stringstream ss;
        ss << body;
        res.set_content(ss.str(), "application/json");
    }

private:
    std::string m_current_code;
    std::vector<Challenge> m_challenges;
    std::vector<Session> m_sessions;
};

int main(int argc, char *argv[])
{
    Api api;

    httplib::Server svr;
    svr.set_mount_point("/", "../frontend");

    svr.Get("/api/v1/challenge", [&api](const auto &req, auto &res) { api.onChallenge(req, res); });
    svr.Post("/api/v1/login", [&api](const auto &req, auto &res) { api.onLogin(req, res); });
    svr.Get("/api/v1/secret", [&api](const auto &req, auto &res) { api.onSecret(req, res); });

    auto host = "0.0.0.0";
    auto port = 8080;
    std::cout << "Listening on http://" << host << ":" << port << "/" << std::endl;
    svr.listen(host, port);

    return 0;
}
