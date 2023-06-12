use casbin::{CoreApi, Enforcer};
use casbin::{RbacApi, Result};
use casbin_rbatis_adapter::CasbinRBatisAdapter;
use rbatis::RBatis;
use rbdc_mysql::driver::MysqlDriver;

#[tokio::main]
async fn main() -> Result<()> {
    println!(r#"mysql_sample"#);
    let rb = RBatis::new();

    let mysql_url = "mysql://casbin:Git785230@mysql-internet-cn-east-2-b5cfacbdb6a34fad.rds.jdcloud.com:3306/casbin";

    // 创建rbatis 实例
    rb.init(MysqlDriver {}, mysql_url).unwrap();
    rb.get_pool().unwrap().resize(10);

    let rb_casbin = CasbinRBatisAdapter::new(rb.clone(), true).await?;
    let mut e = Enforcer::new("examples/rbac_model.conf", rb_casbin).await?;

    // 添加权限
    e.add_permission_for_user("alice", vec!["data1".to_string(), "read".to_string()]).await?;

    let sub = "alice"; // the user that wants to access a resource.
    let obj = "data1"; // the resource that is going to be accessed.
    let act = "read"; // the operation that the user performs on the resource.

    if let Ok(authorized) = e.enforce((sub, obj, act)) {
        if authorized {
            // permit alice to read data1
            println!("pass")
        } else {
            // deny the request
            println!("deny")
        }
    } else {
        // error occurs
        println!("error occurs")
    }

    Ok(())
}
