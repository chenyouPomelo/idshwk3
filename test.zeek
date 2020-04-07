global agentset: set[string]={};
global key: set[string]={"USER-AGENT"};
global my_count=0;
global a:addr;
event http_header(c: connection, is_orig: bool, name: string, value: string)
{
        a=c$id$orig_h;
        if(name in key){
        if(to_lower(value) in agentset){
        ;}
        else{
        ++my_count;
        add agentset[to_lower(value)];
        }
    }
}
event zeek_done(){
     if (my_count >= 3){
        print fmt("%s is a proxy",a);
    }
}
