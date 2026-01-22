package com.trackwize.authentication.provider;

import com.trackwize.common.constant.DBConst;
import com.trackwize.authentication.model.entity.User;
import org.apache.ibatis.jdbc.SQL;

public class UserProvider {

    public String findAll() {
        return new SQL()
                .SELECT("*")
                .FROM(DBConst.USER_TABLE)
                .WHERE("status = " + DBConst.STATUS_ACTIVE_QUERY)
                .toString();
    }

    public String findByEmail(String email) {
        return new SQL()
                .SELECT("*")
                .FROM(DBConst.USER_TABLE)
                .WHERE("email = #{email}")
                .WHERE("status = " + DBConst.STATUS_ACTIVE_QUERY)
                .toString();
    }

    public String findById(Long userId) {
        return new SQL()
                .SELECT("*")
                .FROM(DBConst.USER_TABLE)
                .WHERE("user_id = #{userId}")
                .WHERE("status = " + DBConst.STATUS_ACTIVE_QUERY)
                .toString();
    }

    public String updatePassword(User user) {
        return new SQL()
                .UPDATE(DBConst.USER_TABLE)
                .SET("password = #{password}")
                .WHERE("user_id = #{userId}")
                .WHERE("status <> " + DBConst.STATUS_INACTIVE_QUERY)
                .toString();
    }

    public String create(User user) {
        return new SQL()
                .INSERT_INTO(DBConst.USER_TABLE)
                .VALUES("email", "#{email}")
                .VALUES("password", "#{password}")
                .VALUES("contact_number", "#{contactNumber}")
                .VALUES("name", "#{name}")
                .VALUES("status", "#{status}")
                .VALUES("created_by", "#{createdBy}")
                .VALUES("updated_by", "#{updatedBy}")
                .toString();
    }

    public String updateRecordStatus(String email, String status) {
        return new SQL()
                .UPDATE(DBConst.USER_TABLE)
                .SET("record_status = #{status}")
                .WHERE("email = #{email}")
                .toString();
    }

    public String existsByEmail(String email) {
        return new SQL()
                .SELECT("CASE WHEN COUNT(*) > 0 THEN TRUE ELSE FALSE END")
                .FROM(DBConst.USER_TABLE)
                .WHERE("email = #{email}")
                .WHERE("status <> " + DBConst.STATUS_INACTIVE_QUERY)
                .toString();
    }
}
