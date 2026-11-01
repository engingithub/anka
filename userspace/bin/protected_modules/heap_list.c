struct Node{int value;struct Node *next;};
struct Node *identity(struct Node *p);
int total(struct Node *p);
int main(){
struct Node *p=malloc(sizeof(struct Node));
struct Node *q=malloc(sizeof(struct Node));
struct Node **tail=0;
int result=0;
if((p==0)|(q==0)){return syscall(0,1,0,0);}
p->value=41;
p->next=q;
q->value=1;
q->next=0;
tail=&p->next;
if(*tail!=q){return syscall(0,2,0,0);}
q=identity(p);
result=total(q);
free(p->next);
free(p);
return syscall(0,result-42,0,0);
}
