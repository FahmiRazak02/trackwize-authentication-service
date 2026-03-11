package com.trackwize.authentication.provider;

import com.trackwize.common.constant.DBConst;
import com.trackwize.authentication.model.entity.Token;
import org.apache.ibatis.jdbc.SQL;

public class TokenProvider {

    public String findAll() {
        return new SQL()
                .FROM(DBConst.TOKEN_TABLE)
                .SELECT("*")
                .WHERE("status = " + DBConst.STATUS_ACTIVE_QUERY)
                .toString();
    }

    public String isTokenExist(Long userId) {
        return new SQL()
                .SELECT("COUNT(1)")
                .FROM(DBConst.TOKEN_TABLE)
                .WHERE("user_id = #{userId}")
                .WHERE("status = " + DBConst.STATUS_ACTIVE_QUERY)
                .toString();
    }

    public String createTokenRecord(Token token) {
        return new SQL()
                .INSERT_INTO(DBConst.TOKEN_TABLE)
                .VALUES("user_id", "#{userId}")
                .VALUES("refresh_token", "#{refreshToken}")
                .VALUES("created_by", "#{createdBy}")
                .VALUES("created_date", "NOW()")
                .toString();
    }

    public String updateTokenRecord(Token token) {
        return new SQL()
                .UPDATE(DBConst.TOKEN_TABLE)
                .SET("refresh_token = #{refreshToken}")
                .SET("updated_by = #{updatedBy}")
                .SET("updated_date = NOW()")
                .toString();
    }

    public String findByUserId(Long userId) {
        return new SQL()
                .SELECT("*")
                .FROM(DBConst.TOKEN_TABLE)
                .WHERE("user_id = #{userId}")
                .WHERE("status = " + DBConst.STATUS_ACTIVE_QUERY)
                .ORDER_BY("updated_date DESC")
                .LIMIT(1)
                .toString();
    }

    public String validateRefreshToken(String refreshToken) {
        return new SQL()
                .SELECT("*")
                .FROM(DBConst.TOKEN_TABLE)
                .WHERE("refresh_token = #{refreshToken}")
                .WHERE("status = " + DBConst.STATUS_ACTIVE_QUERY)
                .toString();
    }

    public String deleteById(Long tokenId) {
        return new SQL()
                .UPDATE(DBConst.TOKEN_TABLE)
                .WHERE("token_id = #{tokenId}")
                .SET("status = " + DBConst.STATUS_INACTIVE_CREATE)
                .toString();
    }
}
