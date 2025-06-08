#include "stdafx.h"
#include "constants.h"
#include "config.h"
#include "input.h"
#include "desc_client.h"
#include "desc_manager.h"
#include "protocol.h"
#include "locale_service.h"
#include "db.h"
#include "utils.h"

#ifdef ENABLE_ADVANCED_FLOOD_PROTECTION
#include <mutex>
#include <chrono>
static std::mutex s_floodMutex;
#include <unordered_set>
#include <unordered_map>
#endif

// #define ENABLE_ACCOUNT_W_SPECIALCHARS
bool FN_IS_VALID_LOGIN_STRING(const char* str)
{
	const char* tmp;

	if (!str || !*str)
	{
		return false;
	}

	if (strlen(str) < 2)
	{
		return false;
	}

	for (tmp = str; *tmp; ++tmp)
	{
		if (isdigit(*tmp) || isalpha(*tmp))
		{
			continue;
		}

#ifdef ENABLE_ACCOUNT_W_SPECIALCHARS

		switch (*tmp)
		{
		case ' ':
		case '_':
		case '-':
		case '.':
		case '!':
		case '@':
		case '#':
		case '$':
		case '%':
		case '^':
		case '&':
		case '*':
		case '(':
		case ')':
			continue;
		}

#endif
		return false;
	}

	return true;
}

bool Login_IsInChannelService(const char* c_login)
{
	if (c_login[0] == '[')
	{
		return true;
	}

	return false;
}

CInputAuth::CInputAuth()
{
}

void CInputAuth::Login(LPDESC d, const char* c_pData)
{
#ifdef ENABLE_ADVANCED_FLOOD_PROTECTION
	static std::unordered_map<std::string, std::pair<int, std::chrono::steady_clock::time_point>> s_loginFlood;
	std::string ip = d->GetHostName();

	auto now = std::chrono::steady_clock::now();
	auto& record = s_loginFlood[ip];

	if (std::chrono::duration_cast<std::chrono::seconds>(now - record.second).count() > 1) {
		record.first = 0;
		record.second = now;
	}
	record.first++;

	if (record.first > 5) {
		sys_err("LOGIN FLOOD: IP %s exceeded login attempt limit", ip.c_str());
		d->DelayedDisconnect(5);
		return;
	}
#endif

	TPacketCGLogin3* pinfo = (TPacketCGLogin3*)c_pData;

	if (!g_bAuthServer)
	{
		sys_err("CInputAuth class is not for game server. IP %s might be a hacker.",
			inet_ntoa(d->GetAddr().sin_addr));
		d->DelayedDisconnect(5);
		return;
	}

	char login[LOGIN_MAX_LEN + 1];
	trim_and_lower(pinfo->login, login, sizeof(login));

	char passwd[PASSWD_MAX_LEN + 1];
	strlcpy(passwd, pinfo->passwd, sizeof(passwd));

	sys_log(0, "InputAuth::Login : %s(%d) desc %p",
		login, strlen(login), get_pointer(d));

	// check login string
	if (false == FN_IS_VALID_LOGIN_STRING(login))
	{
		sys_log(0, "InputAuth::Login : IS_NOT_VALID_LOGIN_STRING(%s) desc %p",
			login, get_pointer(d));
		LoginFailure(d, "NOID");
		return;
	}

	if (g_bNoMoreClient)
	{
		TPacketGCLoginFailure failurePacket;

		failurePacket.header = HEADER_GC_LOGIN_FAILURE;
		strlcpy(failurePacket.szStatus, "SHUTDOWN", sizeof(failurePacket.szStatus));

		d->Packet(&failurePacket, sizeof(failurePacket));
		return;
	}

	if (DESC_MANAGER::instance().FindByLoginName(login))
	{
		LoginFailure(d, "ALREADY");
		return;
	}

	DWORD dwKey = DESC_MANAGER::instance().CreateLoginKey(d);

	sys_log(0, "InputAuth::Login: login %s", login);

	TPacketCGLogin3* p = M2_NEW TPacketCGLogin3;
	thecore_memcpy(p, pinfo, sizeof(TPacketCGLogin3));

	char szPasswd[PASSWD_MAX_LEN * 2 + 1];
	DBManager::instance().EscapeString(szPasswd, sizeof(szPasswd), passwd, strlen(passwd));

	char szLogin[LOGIN_MAX_LEN * 2 + 1];
	DBManager::instance().EscapeString(szLogin, sizeof(szLogin), login, strlen(login));

	// CHANNEL_SERVICE_LOGIN
	if (Login_IsInChannelService(szLogin))
	{
		sys_log(0, "ChannelServiceLogin [%s]", szLogin);

		DBManager::instance().ReturnQuery(QID_AUTH_LOGIN, dwKey, p,
			"SELECT '%s',password,securitycode,social_id,id,status,availDt - NOW() > 0,"
			"UNIX_TIMESTAMP(silver_expire),"
			"UNIX_TIMESTAMP(gold_expire),"
			"UNIX_TIMESTAMP(safebox_expire),"
			"UNIX_TIMESTAMP(autoloot_expire),"
			"UNIX_TIMESTAMP(fish_mind_expire),"
			"UNIX_TIMESTAMP(marriage_fast_expire),"
			"UNIX_TIMESTAMP(money_drop_rate_expire),"
			"UNIX_TIMESTAMP(create_time)"
			" FROM account WHERE login='%s'",

			szPasswd, szLogin);
	}

	// END_OF_CHANNEL_SERVICE_LOGIN
	else
	{
#ifdef __WIN32__
		// @fixme138 alternative for mysql8
#define _MYSQL_NATIVE_PASSWORD(str) "CONCAT('*', UPPER(SHA1(UNHEX(SHA1(" str ")))))"
		DBManager::instance().ReturnQuery(QID_AUTH_LOGIN, dwKey, p,
			"SELECT " _MYSQL_NATIVE_PASSWORD("'%s'") ", password, securitycode, social_id, id, status, availDt - NOW() > 0, "
			"UNIX_TIMESTAMP(silver_expire),"
			"UNIX_TIMESTAMP(gold_expire),"
			"UNIX_TIMESTAMP(safebox_expire),"
			"UNIX_TIMESTAMP(autoloot_expire),"
			"UNIX_TIMESTAMP(fish_mind_expire),"
			"UNIX_TIMESTAMP(marriage_fast_expire),"
			"UNIX_TIMESTAMP(money_drop_rate_expire),"
			"UNIX_TIMESTAMP(create_time)"
			" FROM account WHERE login='%s'", szPasswd, szLogin);
#else
		// @fixme138 1. PASSWORD('%s') -> %s 2. szPasswd wrapped inside mysql_hash_password(%s).c_str()
		DBManager::instance().ReturnQuery(QID_AUTH_LOGIN, dwKey, p,
			"SELECT '%s',password,securitycode,social_id,id,status,availDt - NOW() > 0,"
			"UNIX_TIMESTAMP(silver_expire),"
			"UNIX_TIMESTAMP(gold_expire),"
			"UNIX_TIMESTAMP(safebox_expire),"
			"UNIX_TIMESTAMP(autoloot_expire),"
			"UNIX_TIMESTAMP(fish_mind_expire),"
			"UNIX_TIMESTAMP(marriage_fast_expire),"
			"UNIX_TIMESTAMP(money_drop_rate_expire),"
			"UNIX_TIMESTAMP(create_time)"
			" FROM account WHERE login='%s'",
			mysql_hash_password(szPasswd).c_str(), szLogin);
#endif
	}
}

int CInputAuth::Analyze(LPDESC d, BYTE bHeader, const char* c_pData)
{
	if (!g_bAuthServer)
	{
		sys_err("CInputAuth class is not for game server. IP %s might be a hacker.",
			inet_ntoa(d->GetAddr().sin_addr));
		d->DelayedDisconnect(5);
		return 0;
	}

	int iExtraLen = 0;

	if (test_server)
	{
		sys_log(0, " InputAuth Analyze Header[%d] ", bHeader);
	}

	switch (bHeader)
	{
	case HEADER_CG_PONG:
		Pong(d);
		break;

	case HEADER_CG_LOGIN3:
		Login(d, c_pData);
		break;

	case HEADER_CG_HANDSHAKE:
		break;

	default:
		sys_err("This phase does not handle this header %d (0x%x)(phase: AUTH)", bHeader, bHeader);
		break;
	}

	return iExtraLen;
}