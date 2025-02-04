import json
import requests
import traceback
import os
import sqlalchemy
import pandas as pd
import psutil
import jwt
import re
from dateutil import parser
from db_utils import DB
from flask import Flask, request, jsonify
from time import time as tt
from sqlalchemy.orm import sessionmaker
from hashlib import sha256
from elasticsearch_utils import elasticsearch_search
from py_zipkin.util import generate_random_64bit_string
from py_zipkin.zipkin import zipkin_span, ZipkinAttrs, create_http_headers_for_new_span
from ace_logger import Logging
from app import app
from datetime import datetime,timedelta

import pytz
tmzone = 'Asia/Kolkata'
import random
import string


logging = Logging()

db_config = {
    'host': os.environ['HOST_IP'],
    'port': os.environ['LOCAL_DB_PORT'],
    'user': os.environ['LOCAL_DB_USER'],
    'password': os.environ['LOCAL_DB_PASSWORD']
}

def http_transport(encoded_span):
    body = encoded_span
    requests.post(
        'http://servicebridge:80/zipkin',
        data=body,
        headers={'Content-Type': 'application/x-thrift'},
    )
def measure_memory_usage():
    process = psutil.Process()
    memory_info = process.memory_info()
    return memory_info.rss  # Resident Set Size (RSS) in bytes

@app.route('/role_approval', methods=['POST', 'GET'])
def role_approval():
    data = request.json
    logging.info(f"data : {data}")
    user = data.get('user', None)
    flag = data.get('flag', None)
    try:
        memory_before = measure_memory_usage()
        start_time = tt()
    except Exception:
        logging.warning("Failed to start ram and time calc")
        pass
    
    trace_id = generate_random_64bit_string()
    tenant_id = os.environ.get('TENANT_ID',None)

    attr = ZipkinAttrs(
        trace_id=trace_id,
        span_id=generate_random_64bit_string(),
        parent_span_id=None,
        flags=None,
        is_sampled=False,
        tenant_id=tenant_id
    )

    with zipkin_span(
        service_name='user_management',
        span_name='role_approval',
        transport_handler=http_transport,
        zipkin_attrs=attr,
        port=5010,
        sample_rate=0.5
        ):
        try:
            db_config['tenant_id'] = tenant_id
            db = DB('group_access', **db_config)
        except Exception as e:
            logging.error(f"Database connection failed: {e}")
            return {"flag": False, "data": {"message": "Database connection failed."}}

        try:
            current_ist = datetime.now(pytz.timezone('Asia/Kolkata'))
            currentTS = current_ist.strftime('%Y-%m-%d %H:%M:%S')
            if flag == "create":
                new_role_name=data.get('new_role_name', None)
                rights_info=data.get('rights_info',{})

                if not new_role_name:
                    return {"flag": False, "message": "Enter role name"}

                query = "SELECT group_name FROM group_definition"
                existing_roles =db.execute_(query)['group_name'].tolist()
                logging.info(f"existing_roles:{existing_roles}")
                if new_role_name in existing_roles:
                    return {"flag": False, "message": "Role already exists."}

                dictvals = {
                    "Add User":"add_user",
                    "Modify User":"modify_user",
                    "Add Business Rule":"add_business_rule",
                    "Modify Business Rule":"modify_business_rule",
                    "Add Roles":"add_roles",
                    "Modify Roles":"modify_roles",
                    "View All Queues":"view_all_queues",
                    "Modify All Queues":"modify_all_queues",
                    "Master Data Edit":"master_data_edit",
                    "Bulk Transaction":"bulk_transaction",
                    "Approve UAM Maker Activity":"approve_uam_maker_activity",
                    "Reject UAM Maker Activity":"reject_uam_maker_activity",
                    "Approve edits to Master": "approve_edits_to_master",
                    "Reject edit to Master":"reject_edit_to_master",
                    "Approve change in Business Rule":"approve_change_in_business_rule",
                    "Reject change in Business Rule":"reject_change_in_business_rule",
                    "Operation Reports":"operation_reports",
                    "UAM Reports":"uam_reports"
                }
                for right, status in rights_info.items():
                    data_to_insert = {
                        'ROLE_NAME': new_role_name,
                        'DISPLAY_ROLE_RIGHTS': right,
                        'ROLE_RIGHTS': dictvals.get(right, right),
                        'STATUS': 'waiting',
                        'RIGHTS_ASSIGNED_STATUS': 'Yes' if status else 'No',
                        'UAMMAKER': user,
                        'UAMMAKER_DATE': currentTS
                    }
                    logging.info(f"data_to_insert :{data_to_insert}")

                    filtered_data = {k: v for k, v in data_to_insert.items() if v != ''}
                    
                    columns_list = ', '.join(filtered_data.keys())

                    values_list = ', '.join(
                        f"TO_TIMESTAMP('{str(v)}', 'YYYY-MM-DD HH24:MI:SS')" if k == "UAMMAKER_DATE" 
                        else f"'{str(v).replace("'", "''")}'" 
                        for k, v in filtered_data.items()
                    )

                    query = f"INSERT INTO role_rights_modifications ({columns_list}) VALUES ({values_list})"

                    db.execute_(query)


                response_data= {"flag": True, "message": "Role created successfully."}
            
            if flag == "accept":
                role_name = data.get('selected_role', None)
                if not role_name:
                    return jsonify({"flag": False, "message": "Role name is required."})

                query = f"SELECT role_name FROM role_rights_modifications WHERE role_name ='{role_name}' and status='waiting'"
                waiting_roles = db.execute_(query)['role_name'].tolist()
                logging.info(f"waiting_roles:{waiting_roles}")
                if not waiting_roles:
                    return jsonify({"flag": False, "message": "No modifications found for approval"})
                query = "SELECT id FROM group_definition"
                id_df =db.execute_(query)['id'].tolist()
                id_dff=max(id_df)+1
                data_to_insert = {
                    'ID': id_dff,
                    'GROUP_NAME': role_name,
                    'GROUP_DEFINITION': json.dumps({"role": [role_name]}),
                    'GROUP_DEFINITION_TEMPLATE': json.dumps({"roles": ["role"]}),
                    'STATUS': 'enabled',
                    'CREATED_DATE': currentTS,
                    'PREV_STATUS':'enabled'
                }

                filtered_data = {k: v for k, v in data_to_insert.items() if v != ''}

                columns_list = ', '.join(filtered_data.keys())
                values_list = ', '.join(
                    f"TO_TIMESTAMP('{str(v)}', 'YYYY-MM-DD HH24:MI:SS')" if k == "CREATED_DATE"
                    else f"'{str(v).replace("'", "''")}'"
                    for k, v in filtered_data.items()
                )
                insert_query = f"INSERT INTO group_definition ({columns_list}) VALUES ({values_list})"
                db.execute(insert_query)
                logging.info(f'#####insert_query is {insert_query}')
                query_result = db.execute_(insert_query)
                logging.info(f'#####query_result is {query_result}')
                insert_query = f"INSERT INTO attribute_dropdown_definition (ATTRIBUTE_ID,PARENT_ATTRIBUTE_VALUE,VALUE) VALUES ({id_dff},'','{role_name}')"
                db.execute(insert_query)
                insert_query = f"INSERT INTO organisation_attributes (SOURCE,ATTRIBUTE,ATT_ID) VALUES ('user','role','{id_dff}')"
                db.execute(insert_query)
                insert_query = f"INSERT INTO organisation_hierarchy(ID,H_GROUP,SOURCE,H_ORDER,PARENT) VALUES ('{id_dff}','roles','user','role','')"
                db.execute(insert_query)
                query = f"UPDATE role_rights_modifications SET status = 'completed' WHERE role_name = '{role_name}'"
                db.execute(query)

                query = f"""
                INSERT INTO role_rights (
                    ROLE_NAME,
                    DISPLAY_ROLE_RIGHTS,
                    ROLE_RIGHTS,
                    STATUS,
                    NEW_RIGHTS_ASSIGNED_STATUS,
                    UAMMAKER,
                    UAMMAKER_DATE,
                    UAMCHECKER,
                    UAMCHECKER_DATE,
                    OLD_RIGHTS_ASSIGNED_STATUS
                )
                SELECT 
                    ROLE_NAME,
                    DISPLAY_ROLE_RIGHTS,
                    ROLE_RIGHTS,
                    'enabled',
                    RIGHTS_ASSIGNED_STATUS AS OLD_RIGHTS_ASSIGNED_STATUS,
                    UAMMAKER,
                    UAMMAKER_DATE,
                    '{user}' AS UAMCHECKER, 
                    TO_TIMESTAMP('{currentTS}', 'YYYY-MM-DD HH24:MI:SS') AS UAMCHECKER_DATE,   
                    NULL
                FROM role_rights_modifications WHERE role_name = '{role_name}'
                """
                logging.info(f'#####insert_query is {insert_query}')
                query_result = db.execute_(query)
                logging.info(f'#####query_result is {query_result}')

                print("Role rights modification and insertion completed successfully!")
                response_data={"flag": True, "message": "Role approved successfully"}
                return response_data

            if flag == "reject":
                role_name = data.get('selected_role', None)
                rejected_comments=data.get('approval_comment',None)

                query = f"""
                    UPDATE role_rights_modifications 
                    SET rejected_comments = '{rejected_comments}', status = 'rejected' 
                    WHERE role_name = '{role_name}' and status='waiting'
                """
                db.execute_(query)

                response_data = {"flag": True,"message": "Role rejected successfully."}
                return response_data
            
        except Exception as e:
                logging.info("Something went wrong in updating data:", {e})
                response_data={"flag": False,"message":"Something went wrong"}

        try:
            memory_after = measure_memory_usage()
            memory_consumed = (memory_after - memory_before) / \
                (1024 * 1024 * 1024)
            end_time = tt()
            time_consumed = str(end_time-start_time)
            memory_consumed = f"{memory_consumed:.10f}"
            time_consumed = str(round(end_time-start_time, 3))
        except:
            logging.warning("Failed to calc end of ram and time")
            logging.exception("ram calc went wrong")
            memory_consumed = None
            time_consumed = None
            pass

        return jsonify(response_data)

@app.route('/update_role_rights', methods=['POST', 'GET'])
def update_role_rights():
    data = request.json
    logging.info(f"data : {data}")
    user = data.get('user', None)
    flag=data.get('flag',None)
    try:
        memory_before = measure_memory_usage()
        start_time = tt()
    except Exception:
        logging.warning("Failed to start ram and time calc")
        pass
    
    trace_id = generate_random_64bit_string()
    tenant_id = os.environ.get('TENANT_ID',None)

    attr = ZipkinAttrs(
        trace_id=trace_id,
        span_id=generate_random_64bit_string(),
        parent_span_id=None,
        flags=None,
        is_sampled=False,
        tenant_id=tenant_id
    )

    with zipkin_span(
        service_name='user_management',
        span_name='update_role_rights',
        transport_handler=http_transport,
        zipkin_attrs=attr,
        port=5010,
        sample_rate=0.5
        ):
        try:
            db_config['tenant_id'] = tenant_id
            db = DB('group_access', **db_config)
        except Exception as e:
            logging.error(f"Database connection failed: {e}")
            return {"flag": False, "data": {"message": "Database connection failed."}}

        try:
            current_ist = datetime.now(pytz.timezone('Asia/Kolkata'))
            currentTS = current_ist.strftime('%Y-%m-%d %H:%M:%S')
            if flag=='update':
                updated_rights=data.get('updated_rights', {})

                query = f"SELECT role_name FROM role_rights_modifications WHERE status='waiting'"
                waiting_roles = db.execute_(query)['role_name'].tolist()
                
                for exist_role,rights_info_df in updated_rights.items():
                    if exist_role in waiting_roles:
                        return jsonify({"flag": False, "message": "Already waiting for approval"})
                    is_role_enabled='enabled' if rights_info_df.get('isRoleEnabled')==True else 'disabled'
                    rights_info=rights_info_df.get('rights_assigned',{})

                    dictvals = {
                    "Add User":"add_user",
                    "Modify User":"modify_user",
                    "Add Business Rule":"add_business_rule",
                    "Modify Business Rule":"modify_business_rule",
                    "Add Roles":"add_roles",
                    "Modify Roles":"modify_roles",
                    "View All Queues":"view_all_queues",
                    "Modify All Queues":"modify_all_queues",
                    "Master Data Edit":"master_data_edit",
                    "Bulk Transaction":"bulk_transaction",
                    "Approve UAM Maker Activity":"approve_uam_maker_activity",
                    "Reject UAM Maker Activity":"reject_uam_maker_activity",
                    "Approve edits to Master": "approve_edits_to_master",
                    "Reject edit to Master":"reject_edit_to_master",
                    "Approve change in Business Rule":"approve_change_in_business_rule",
                    "Reject change in Business Rule":"reject_change_in_business_rule",
                    "Operation Reports":"operation_reports",
                    "UAM Reports":"uam_reports"
                    }
                    for right, status in rights_info.items():
                        data_to_insert = {
                            'ROLE_NAME': exist_role,
                            'DISPLAY_ROLE_RIGHTS': right,
                            'ROLE_RIGHTS': dictvals.get(right, right),
                            'STATUS': 'waiting',
                            'RIGHTS_ASSIGNED_STATUS': 'Yes' if status else 'No',
                            'UAMMAKER': user,
                            'UAMMAKER_DATE': currentTS
                        }
                        logging.info(f"data_to_insert :{data_to_insert}")

                        filtered_data = {k: v for k, v in data_to_insert.items() if v != ''}
                        
                        columns_list = ', '.join(filtered_data.keys())

                        values_list = ', '.join(
                            f"TO_TIMESTAMP('{str(v)}', 'YYYY-MM-DD HH24:MI:SS')" if k == "UAMMAKER_DATE" 
                            else f"'{str(v).replace("'", "''")}'" 
                            for k, v in filtered_data.items()
                        )

                        query = f"INSERT INTO role_rights_modifications ({columns_list}) VALUES ({values_list})"

                        db.execute_(query)
                    
                    query = f"UPDATE group_definition SET prev_status ='{is_role_enabled}' WHERE group_name = '{exist_role}'"
                    db.execute_(query)

                response_data= {"flag": True, "message": "Role updated successfully."}
            if flag=='approve':
                role=data.get("selected_role")
                query = "UPDATE role_rights SET old_rights_assigned_status = new_rights_assigned_status WHERE role_name = '{role}'"
                db.execute_(query)
                query=f"""
                    UPDATE role_rights rr
                    SET NEW_RIGHTS_ASSIGNED_STATUS = (
                        SELECT rrm.RIGHTS_ASSIGNED_STATUS
                        FROM role_rights_modifications rrm
                        WHERE rr.ROLE_NAME = rrm.ROLE_NAME
                        AND rr.ROLE_RIGHTS = rrm.ROLE_RIGHTS
                        AND rrm.status = 'waiting'
                        FETCH FIRST 1 ROW ONLY
                    )
                    WHERE rr.ROLE_NAME = '{role}'
                    AND EXISTS (
                        SELECT 1 FROM role_rights_modifications rrm
                        WHERE rr.ROLE_NAME = rrm.ROLE_NAME
                        AND rr.ROLE_RIGHTS = rrm.ROLE_RIGHTS
                        AND rrm.status = 'waiting'
                    )
                """
                db.execute_(query)

                query = f"UPDATE role_rights_modifications SET status = 'completed' WHERE role_name = '{role}' and status='waiting'"
                db.execute_(query)

                query = f"UPDATE group_definition SET status = prev_status,disabled_date=TO_TIMESTAMP('{currentTS}', 'YYYY-MM-DD HH24:MI:SS') WHERE group_name = '{role}'"
                db.execute_(query)
                response_data= {"flag": True, "message": "Role Approved successfully."}

            if flag=='reject':
                role_name = data.get('selected_role', None)
                rejected_comments=data.get('rejected_comments',None)

                query1 = f"SELECT role_rights,rights_assigned_status FROM role_rights_modifications WHERE role_name='{role_name}' and status='waiting'"
                query2 = f"SELECT role_rights,new_rights_assigned_status FROM role_rights WHERE role_name='{role_name}'"
                df_modifications=db.execute_(query1)
                df_rights= db.execute_(query2)
                df_merged = pd.merge(df_modifications, df_rights, on="role_rights", how="inner")
                df_mismatch = df_merged[df_merged["rights_assigned_status"] != df_merged["new_rights_assigned_status"]]

                mismatched_role_rights = df_mismatch["role_rights"].tolist()

                rights_tuple = tuple(mismatched_role_rights) if len(mismatched_role_rights) > 1 else f"('{mismatched_role_rights[0]}')"

                logging.info(f'mismatched_role_rights{mismatched_role_rights}')
                query = f"""
                    UPDATE role_rights_modifications 
                    SET rejected_comments = '{rejected_comments}' 
                    WHERE role_name = '{role_name}' and status='waiting' and role_rights in {rights_tuple}
                """
                db.execute_(query)
                
                query = f"""
                    UPDATE role_rights_modifications 
                    SET status = 'rejected'
                    WHERE role_name = '{role_name}' and status='waiting'
                """
                db.execute_(query)
                response_data = {"flag": True,"message": "Role rejected successfully."}
                return response_data
            
        except Exception as e:
                logging.info("Something went wrong in updating data:", {e})
                response_data={"flag": False,"message":"Something went wrong"}

        try:
            memory_after = measure_memory_usage()
            memory_consumed = (memory_after - memory_before) / \
                (1024 * 1024 * 1024)
            end_time = tt()
            time_consumed = str(end_time-start_time)
            memory_consumed = f"{memory_consumed:.10f}"
            time_consumed = str(round(end_time-start_time, 3))
        except:
            logging.warning("Failed to calc end of ram and time")
            logging.exception("ram calc went wrong")
            memory_consumed = None
            time_consumed = None
            pass

        return jsonify(response_data)