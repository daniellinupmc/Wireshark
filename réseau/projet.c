#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#define TAILLE_MAX 10000

int main(){
    FILE *fichier=NULL;
    FILE *ecriture=NULL;
    char ch[54];
    char chaine[TAILLE_MAX];
    fichier=fopen("trame.txt","r");
    ecriture=fopen("analyse.txt","w");
    if(fichier!=NULL){
        while(fgets(ch,54,fichier)){
            strcat(chaine,ch);
        }
        //Ethernet
        printf("Ethernet II\n");
        fputs("Ethernet II\n",ecriture);
        //Adresse destination et source
        printf("    Destination: %c%c:%c%c:%c%c:%c%c:%c%c:%c%c\n",chaine[7],chaine[8],chaine[10],chaine[11],chaine[13],chaine[14],chaine[16],chaine[17],chaine[19],chaine[20],chaine[22],chaine[23]);
        fprintf(ecriture,"    Destination: %c%c:%c%c:%c%c:%c%c:%c%c:%c%c\n",chaine[7],chaine[8],chaine[10],chaine[11],chaine[13],chaine[14],chaine[16],chaine[17],chaine[19],chaine[20],chaine[22],chaine[23]);
        printf("    Source: %c%c:%c%c:%c%c:%c%c:%c%c:%c%c\n",chaine[25],chaine[26],chaine[28],chaine[29],chaine[31],chaine[32],chaine[34],chaine[35],chaine[37],chaine[38],chaine[40],chaine[41]);
        fprintf(ecriture,"    Source: %c%c:%c%c:%c%c:%c%c:%c%c:%c%c\n",chaine[25],chaine[26],chaine[28],chaine[29],chaine[31],chaine[32],chaine[34],chaine[35],chaine[37],chaine[38],chaine[40],chaine[41]);
        //Type
        char type[5];
        type[0]=chaine[43];
        type[1]=chaine[44];
        type[2]=chaine[46];
        type[3]=chaine[47];
        char type1[5]="0800";
        char type2[5]="86dd";
        char type3[5]="0806";
        char type4[5]="8035";
        char type5[5]="809b";
        char type6[5]="88cd";
        char type7[5]="0600";
        char type8[5]="8100";
        if(strcmp(type,type1)==0){
            printf("    Type: IPv4 (0x%s)\n",type);
            fprintf(ecriture,"    Type: IPv4 (0x%s)\n",type);
        }
        if(strcmp(type,type2)==0){
            printf("    Type: IPv6 (0x%s)\n",type);
            fprintf(ecriture,"    Type: IPv6 (0x%s)\n",type);
        }
        if(strcmp(type,type3)==0){
            printf("    Type: ARP (0x%s)\n",type);
            fprintf(ecriture,"    Type: ARP (0x%s)\n",type);
        }
        if(strcmp(type,type4)==0){
            printf("    Type: RARP (0x%s)\n",type);
            fprintf(ecriture,"    Type: RARP (0x%s)\n",type);
        }
        if(strcmp(type,type5)==0){
            printf("    Type: AppleTalk (0x%s)\n",type);
            fprintf(ecriture,"    Type: AppleTalk (0x%s)\n",type);
        }
        if(strcmp(type,type6)==0){
            printf("    Type: SERCOS III (0x%s)\n",type);
            fprintf(ecriture,"    Type: SERCOS III (0x%s)\n",type);
        }
        if(strcmp(type,type7)==0){
            printf("    Type: XNS (0x%s)\n",type);
            fprintf(ecriture,"    Type: XNS (0x%s)\n",type);
        }
        if(strcmp(type,type8)==0){
            printf("    Type: VLAN (0x%s)\n",type);
            fprintf(ecriture,"    Type: VLAN (0x%s)\n",type);
        }
        //IP
        //Version
        int version=(int)chaine[49];
        version-='0';
        if(version==6){
            printf("Internet Protocol Version 6\n");
            fputs("Internet Protocol Version 6\n",ecriture);
            printf("    0110 .... = Version: 6\n");
            fputs("    0110 .... = Version: 6\n",ecriture);
        }else{
            printf("Internet Protocol Version 4\n");
            fputs("Internet Protocol Version 4\n",ecriture);
            printf("    0100 .... = Version: 4\n");
            fputs("    0100 .... = Version: 4\n",ecriture);
        }
        if(version==4){
            //Version 4
            //Header Length
            int hlengthip=(int)chaine[50];
            if(hlengthip>=97 && hlengthip<=102){
                hlengthip-=87;
            }else{
                hlengthip-='0';
            }
            int length=hlengthip;
            hlengthip=hlengthip*4;
            if(length-8>=0){
                length-=8;
                if(length-4>=0){
                    length-=4;
                    if(length-2>=0){
                        length-=2;
                        if(length-1>=0){
                            length-=1;
                            printf("    .... 1111 = Header Length: %d bytes (%c)\n",hlengthip,chaine[50]);
                            fprintf(ecriture,"    .... 1111 = Header Length: %d bytes (%c)\n",hlengthip,chaine[50]);
                        }else{
                            printf("    .... 1110 = Header Length: %d bytes (%c)\n",hlengthip,chaine[50]);
                            fprintf(ecriture,"    .... 1110 = Header Length: %d bytes (%c)\n",hlengthip,chaine[50]);
                        }
                    }else{
                        if(length-1>=0){
                            length-=1;
                            printf("    .... 1101 = Header Length: %d bytes (%c)\n",hlengthip,chaine[50]);
                            fprintf(ecriture,"    .... 1101 = Header Length: %d bytes (%c)\n",hlengthip,chaine[50]);
                        }else{
                            printf("    .... 1100 = Header Length: %d bytes (%c)\n",hlengthip,chaine[50]);
                            fprintf(ecriture,"    .... 1100 = Header Length: %d bytes (%c)\n",hlengthip,chaine[50]);
                        }
                    }
                }else{
                    if(length-2>=0){
                        length-=2;
                        if(length-1>=0){
                           length-=1;
                            printf("    .... 1011 = Header Length: %d bytes (%c)\n",hlengthip,chaine[50]);
                            fprintf(ecriture,"    .... 1011 = Header Length: %d bytes (%c)\n",hlengthip,chaine[50]);
                        }else{
                            printf("    .... 1010 = Header Length: %d bytes (%c)\n",hlengthip,chaine[50]);
                            fprintf(ecriture,"    .... 1010 = Header Length: %d bytes (%c)\n",hlengthip,chaine[50]);
                        }
                    }else{
                        if(length-1>=0){
                            length-=1;
                            printf("    .... 1001 = Header Length: %d bytes (%c)\n",hlengthip,chaine[50]);
                            fprintf(ecriture,"    .... 1001 = Header Length: %d bytes (%c)\n",hlengthip,chaine[50]);
                        }else{
                            printf("    .... 1000 = Header Length: %d bytes (%c)\n",hlengthip,chaine[50]);
                            fprintf(ecriture,"    .... 1000 = Header Length: %d bytes (%c)\n",hlengthip,chaine[50]);
                        }
                    }
                }
            }else{
                if(length-4>=0){
                    length-=4;
                    if(length-2>=0){
                        length-=2;
                        if(length-1>=0){
                            length-=1;
                            printf("    .... 0111 = Header Length: %d bytes (%c)\n",hlengthip,chaine[50]);
                            fprintf(ecriture,"    .... 0111 = Header Length: %d bytes (%c)\n",hlengthip,chaine[50]);
                        }else{
                            printf("    .... 0110 = Header Length: %d bytes (%c)\n",hlengthip,chaine[50]);
                            fprintf(ecriture,"    .... 0110 = Header Length: %d bytes (%c)\n",hlengthip,chaine[50]);
                        }
                    }else{
                        if(length-1>=0){                
                            length-=1;
                            printf("    .... 0101 = Header Length: %d bytes (%c)\n",hlengthip,chaine[50]);
                            fprintf(ecriture,"    .... 0101 = Header Length: %d bytes (%c)\n",hlengthip,chaine[50]);
                        }
                    }
                }
            }
            //Type of Service
            printf("    Differentiated Services Field: 0x%c%c\n",chaine[52],chaine[53]);
            fprintf(ecriture,"    Differentiated Services Field: 0x%c%c\n",chaine[52],chaine[53]);
            printf("        Differentiated Services Codepoint: Default (%c)\n",chaine[52]);
            fprintf(ecriture,"        Differentiated Services Codepoint: Default (%c)\n",chaine[52]);
            printf("        Explicit Congestion Notification: Not ECN-Capable Transport (%c)\n",chaine[53]);
            fprintf(ecriture,"        Explicit Congestion Notification: Not ECN-Capable Transport (%c)\n",chaine[53]);
            //Total Length
            int length3=(int)chaine[62];
            if(length3>=97 && length3<=102){
                length3-=87;
            }else{
                length3-='0';
            }
            length3=length3*pow(16,3);
            int length2=(int)chaine[63];
            if(length2>=97 && length2<=102){
                length2-=87;
            }else{
                length2-='0';
            }
            length2=length2*pow(16,2);
            int length1=(int)chaine[65];
            if(length1>=97 && length1<=102){
                length1-=87;
            }else{
                length1-='0';
            }
            length1=length1*pow(16,1);
            int length0=(int)chaine[66];
            if(length0>=97 && length0<=102){
                length0-=87;
            }else{
                length0-='0';
            }
            length0=length0*pow(16,0);
            printf("    Total Length: 0x%c%c%c%c (%d)\n",chaine[62],chaine[63],chaine[65],chaine[66],length0+length1+length2+length3);
            fprintf(ecriture,"    Total Length: 0x%c%c%c%c (%d)\n",chaine[62],chaine[63],chaine[65],chaine[66],length0+length1+length2+length3);
            //Identification
            int id3=(int)chaine[68];
            if(id3>=97 && id3<=102){
                id3-=87;
            }else{
                id3-='0';
            }
            id3=id3*pow(16,3);
            int id2=(int)chaine[69];
            if(id2>=97 && id2<=102){
                id2-=87;
            }else{
                id2-='0';
            }
            id2=id2*pow(16,2);
            int id1=(int)chaine[71];
            if(id1>=97 && id1<=102){
                id1-=87;
            }else{
                id1-='0';
            }
            id1=id1*pow(16,1);
            int id0=(int)chaine[72];
            if(id0>=97 && id0<=102){
                id0-=87;
            }else{
                id0-='0';
            }
            id0=id0*pow(16,0);
            printf("    Identification: 0x%c%c%c%c (%d)\n",chaine[68],chaine[69],chaine[71],chaine[72],id0+id1+id2+id3);
            fprintf(ecriture,"    Identification: 0x%c%c%c%c (%d)\n",chaine[68],chaine[69],chaine[71],chaine[72],id0+id1+id2+id3);
            //Flags
            int flag=(int)chaine[74];
            flag-='0';
            printf("    Flags: 0x%c%c\n",chaine[74],chaine[75]);
            fprintf(ecriture,"    Flags: 0x%c%c\n",chaine[74],chaine[75]);
            printf("        0... .... = Reserved bit: Not set\n");
            fputs("        0... .... = Reserved bit: Not set\n",ecriture);
            if(flag-4>=0){
                flag-=4;
                printf("        .1.. .... = Don't fragment: Set\n");
                fputs("        .1.. .... = Don't fragment: Set\n",ecriture);
            }else{
                printf("        .0.. .... = Don't fragment: Not set\n");
                fputs("        .0.. .... = Don't fragment: Not set\n",ecriture);
            }
            if(flag-2>=0){
                flag-=2;
                printf("        ..1. .... = More fragments: Set\n");
                fputs("        ..1. .... = More fragments: Set\n",ecriture);
            }else{
                printf("        ..0. .... = More fragments: Not set\n");
                fputs("        ..0. .... = More fragments: Not set\n",ecriture);
            }
            //Fragment Offset
            int foadd=0;
            int fo0;
            if(flag-1>=0){
                fo0=1*pow(2,12);
            }
            int fo1=(int)chaine[75];
            if(fo1>=97 && fo1<=102){
                fo1-=87;
            }else{
                fo1-='0';
            }
            if(fo1-8>=0){
                fo1-=8;
                foadd=foadd+(1*pow(2,11));
            }
            if(fo1-4>=0){
                fo1-=4;
                foadd=foadd+(1*pow(2,10));
            }        
            if(fo1-2>=0){
                fo1-=2;
                foadd=foadd+(1*pow(2,9));
            }
            if(fo1-1>=0){
                fo1-=1;
                foadd=foadd+(1*pow(2,8));
            }
            int fo2=(int)chaine[77];
            if(fo2>=97 && fo2<=102){
                fo2-=87;
            }else{
                fo2-='0';
            }
            if(fo2-8>=0){
                fo2-=8;
                foadd=foadd+(1*pow(2,7));
            }
            if(fo2-4>=0){
                fo2-=4;
                foadd=foadd+(1*pow(2,6));
            }
            if(fo2-2>=0){
                fo2-=2;
                foadd=foadd+(1*pow(2,5));
            }
            if(fo2-1>=0){
                fo2-=1;
                foadd=foadd+(1*pow(2,4));
            }
            int fo3=(int)chaine[78];
            if(fo3>=97 && fo3<=102){
                fo3-=87;
            }else{
                fo3-='0';
            }
            if(fo3-8>=0){
                fo3-=8;
                foadd=foadd+(1*pow(2,3));
            }
            if(fo3-4>=0){
                fo3-=4;
                foadd=foadd+(1*pow(2,2));
            }
            if(fo3-2>=0){
                fo3-=2;
                foadd=foadd+(1*pow(2,1));
            }
            if(fo3-1>=0){
                fo3-=1;;
                foadd=foadd+(1*pow(2,0));
            }
            printf("    Fragment Offset: %d\n",foadd);
            fprintf(ecriture,"    Fragment Offset: %d\n",foadd);
            //Time to Live
            int t1=(int)chaine[80];
            if(t1>=97 && t1<=102){
                t1-=87;
            }else{
                t1-='0';
            }
            t1=t1*pow(16,1);
            int t2=(int)chaine[81];
            if(t2>=97 && t2<=102){
                t2-=87;
            }else{
                t2-='0';
            }
            t2=t2*pow(16,0);
            printf("    Time to Live: %d\n",t1+t2);
            fprintf(ecriture,"    Time to Live: %d\n",t1+t2);
            //Protocol
            int p1=(int)chaine[83];
            if(p1>=97 && p1<=102){
                p1-=87;
            }else{
                p1-='0';
            }
            p1=p1*pow(16,1);
            int p2=(int)chaine[84];
            if(p2>=97 && p2<=102){
                p2-=87;
            }else{
                p2-='0';
            }
            p2=p2*pow(16,0);
            if(p1+p2==1){
                printf("    Protocol: ICMP (1)\n");
                fputs("    Protocol: ICMP (1)\n",ecriture);
            }if(p1+p2==2){
                printf("    Protocol: IGMP (2)\n");
                fputs("    Protocol: IGMP (2)\n",ecriture);
            }if(p1+p2==6){
                printf("    Protocol: TCP (6)\n");
                fputs("    Protocol: TCP (6)\n",ecriture);
            }if(p1+p2==17){
                printf("    Protocol: UDP (17)\n");
                fputs("    Protocol: UDP (17)\n",ecriture);
            }
            //Header Checksum
            printf("    Header Checksum: 0x%c%c%c%c\n",chaine[86],chaine[87],chaine[89],chaine[90]);
            fprintf(ecriture,"    Header Checksum: 0x%c%c%c%c\n",chaine[86],chaine[87],chaine[89],chaine[90]);
            //Source Address
            int ips0=(int)chaine[92];
            if(ips0>=97 && ips0<=102){
                ips0-=87;
            }else{
                ips0-='0';
            }
            ips0=ips0*pow(16,1);
            int ips1=(int)chaine[93];
            if(ips1>=97 && ips1<=102){
                ips1-=87;
            }else{
                ips1-='0';
            }
            ips1=ips1*pow(16,0);
            int ips2=(int)chaine[95];
            if(ips2>=97 && ips2<=102){
                ips2-=87;
            }else{
                ips2-='0';
            }
            ips2=ips2*pow(16,1);
            int ips3=(int)chaine[96];
            if(ips3>=97 && ips3<=102){
                ips3-=87;
            }else{
                ips3-='0';
            }
            ips3=ips3*pow(16,0);
            int ips4=(int)chaine[98];
            if(ips4>=97 && ips4<=102){
                ips4-=87;
            }else{
                ips4-='0';
            }
            ips4=ips4*pow(16,1);
            int ips5=(int)chaine[99];
            if(ips5>=97 && ips5<=102){
                ips5-=87;
            }else{
                ips5-='0';
            }
            ips5=ips5*pow(16,0);
            int ips6=(int)chaine[101];
            if(ips6>=97 && ips6<=102){
                ips6-=87;
            }else{
                ips6-='0';
            }
            ips6=ips6*pow(16,1);
            int ips7=(int)chaine[102];
            if(ips7>=97 && ips7<=102){
                ips7-=87;
            }else{
                ips7-='0';
            }
            ips7=ips7*pow(16,0);
            printf("    Source Address: %d.%d.%d.%d\n",ips0+ips1,ips2+ips3,ips4+ips5,ips6+ips7);
            fprintf(ecriture,"    Source Address: %d.%d.%d.%d\n",ips0+ips1,ips2+ips3,ips4+ips5,ips6+ips7);
            //Destination Address
            int ipd0=(int)chaine[104];
            if(ipd0>=97 && ipd0<=102){
                ipd0-=87;
            }else{
                ipd0-='0';
            }
            ipd0=ipd0*pow(16,1);
            int ipd1=(int)chaine[105];
            if(ipd1>=97 && ipd1<=102){
                ipd1-=87;
            }else{
                ipd1-='0';
            }
            ipd1=ipd1*pow(16,0);
            int ipd2=(int)chaine[107];
            if(ipd2>=97 && ipd2<=102){
                ipd2-=87;
            }else{
                ipd2-='0';
            }
            ipd2=ipd2*pow(16,1);
            int ipd3=(int)chaine[108];
            if(ipd3>=97 && ipd3<=102){
                ipd3-=87;
            }else{
                ipd3-='0';
            }
            ipd3=ipd3*pow(16,0);
            int ipd4=(int)chaine[117];
            if(ipd4>=97 && ipd4<=102){
                ipd4-=87;
            }else{
                ipd4-='0';
            }
            ipd4=ipd4*pow(16,1);
            int ipd5=(int)chaine[118];
            if(ipd5>=97 && ipd5<=102){
                ipd5-=87;
            }else{
                ipd5-='0';
            }
            ipd5=ipd5*pow(16,0);
            int ipd6=(int)chaine[120];
            if(ipd6>=97 && ipd6<=102){
                ipd6-=87;
            }else{
                ipd6-='0';
            }
            ipd6=ipd6*pow(16,1);
            int ipd7=(int)chaine[121];
            if(ipd7>=97 && ipd7<=102){
                ipd7-=87;
            }else{
                ipd7-='0';
            }
            ipd7=ipd7*pow(16,0);
            printf("    Destination Address: %d.%d.%d.%d\n",ipd0+ipd1,ipd2+ipd3,ipd4+ipd5,ipd6+ipd7);
            fprintf(ecriture,"    Destination Address: %d.%d.%d.%d\n",ipd0+ipd1,ipd2+ipd3,ipd4+ipd5,ipd6+ipd7);
            //Options
            int valueip=123;
            if(hlengthip>20){
                int optlengthip=20;
                printf("    Options: (%d bytes)\n",hlengthip-optlengthip);
                fprintf(ecriture,"    Options: (%d bytes)\n",hlengthip-optlengthip);
                while(hlengthip>optlengthip){
                    int optip0=(int)chaine[valueip];
                    int optip1=(int)chaine[valueip+1];
                    if(optip0>=97 && optip0<=102){
                        optip0-=87;
                    }else{
                        optip0-='0';
                    }
                    optip0=optip0*pow(16,1);
                    if(optip1>=97 && optip1<=102){
                        optip1-=87;
                    }else{
                        optip1-='0';
                    }
                    optip1=optip1*pow(16,0);
                    if(optip0+optip1==0){
                        printf("        IP Option - End of Option List (EOOL)\n");
                        fputs("        IP Option -End of Option List (EOOL)\n",ecriture);
                        printf("            Type: %d\n",optip0+optip1);
                        fprintf(ecriture,"            Type: %d\n",optip0+optip1);
                        optlengthip++;
                        if(chaine[valueip+2]=='\n'){
                            valueip+=10;
                        }else{
                            valueip+=3;
                        }
                    }
                    if(optip0+optip1==1){
                        printf("        IP Option - No-Operation (NOP)\n");
                        fputs("        IP Option - No-Operation (NOP)\n",ecriture);
                        printf("            Type: %d\n",optip0+optip1);
                        fprintf(ecriture,"            Type: %d\n",optip0+optip1);
                        optlengthip++;
                        if(chaine[valueip+2]=='\n'){
                            valueip+=10;
                        }else{
                            valueip+=3;
                        }
                    }
                }
            }
            //TCP
            printf("Transmission Control Protocol\n");
            fputs("Transmission Control Protocol\n",ecriture);
            //Source Port
            int sp0=(int)chaine[valueip];
            if(sp0>=97 && sp0<=102){
                sp0-=87;
            }else{
                sp0-='0';
            }
            sp0=sp0*pow(16,3);
            int sp1=(int)chaine[valueip+1];
            if(sp1>=97 && sp1<=102){
                sp1-=87;
            }else{
                sp1-='0';
            }
            sp1=sp1*pow(16,2);
            int sp2=(int)chaine[valueip+3];
            if(sp2>=97 && sp2<=102){
                sp2-=87;
            }else{
                sp2-='0';
            }
            sp2=sp2*pow(16,1);
            int sp3=(int)chaine[valueip+4];
            if(sp3>=97 && sp3<=102){
                sp3-=87;
            }else{
                sp3-='0';
            }
            sp3=sp3*pow(16,0);
            printf("    Source Port: %d\n",sp0+sp1+sp2+sp3);
            fprintf(ecriture,"    Source Port: %d\n",sp0+sp1+sp2+sp3);
            //Destination Port
            int dp0=(int)chaine[129];
            if(dp0>=97 && dp0<=102){
                dp0-=87;
            }else{
                dp0-='0';
            }
            dp0=dp0*pow(16,3);
            int dp1=(int)chaine[130];
            if(dp1>=97 && dp1<=102){
                dp1-=87;
            }else{
                dp1-='0';
            }
            dp1=dp1*pow(16,2);
            int dp2=(int)chaine[132];
            if(dp2>=97 && dp2<=102){
                dp2-=87;
            }else{
                dp2-='0';
            }
            dp2=dp2*pow(16,1);
            int dp3=(int)chaine[133];
            if(dp3>=97 && dp3<=102){
                dp3-=87;
            }else{
                dp3-='0';
            }
            dp3=dp3*pow(16,0);
            printf("    Destination Port: %d\n",dp0+dp1+dp2+dp3);
            fprintf(ecriture,"    Destination Port: %d\n",dp0+dp1+dp2+dp3);
            //Sequence
            int s0=(int)chaine[135];
            if(s0>=97 && s0<=102){
                s0-=87;
            }else{
                s0-='0';
            }
            s0=s0*pow(16,7);
            int s1=(int)chaine[136];
            if(s1>=97 && s1<=102){
                s1-=87;
            }else{
                s1-='0';
            }
            s1=s1*pow(16,6);
            int s2=(int)chaine[138];
            if(s2>=97 && s2<=102){
                s2-=87;
            }else{
                s2-='0';
            }
            s2=s2*pow(16,5);
            int s3=(int)chaine[139];
            if(s3>=97 && s3<=102){
                s3-=87;
            }else{
                s3-='0';
            }
            s3=s3*pow(16,4);
            int s4=(int)chaine[141];
            if(s4>=97 && s4<=102){
                s4-=87;
            }else{
                s4-='0';
            }
            s4=s4*pow(16,3);
            int s5=(int)chaine[142];
            if(s5>=97 && s5<=102){
                s5-=87;
            }else{
                s5-='0';
            }
            s5=s5*pow(16,2);
            int s6=(int)chaine[144];
            if(s6>=97 && s6<=102){
                s6-=87;
            }else{
                s6-='0';
            }
            s6=s6*pow(16,1);
            int s7=(int)chaine[145];
            if(s7>=97 && s7<=102){
                s7-=87;
            }else{
                s7-='0';
            }
            s7=s7*pow(16,0);
            printf("    Sequence Number: %d\n",s0+s1+s2+s3+s4+s5+s6+s7);
            fprintf(ecriture,"    Sequence Number: %d\n",s0+s1+s2+s3+s4+s5+s6+s7);
            //Acknowledgment Number
            int ack0=(int)chaine[147];
            if(ack0>=97 && ack0<=102){
                ack0-=87;
            }else{
                ack0-='0';
            }
            ack0=ack0*pow(16,7);
            int ack1=(int)chaine[148];
            if(ack1>=97 && ack1<=102){
                ack1-=87;
            }else{
                ack1-='0';
            }
            ack1=ack1*pow(16,6);
            int ack2=(int)chaine[150];
            if(ack2>=97 && ack2<=102){
                ack2-=87;
            }else{
                ack2-='0';
            }
            ack2=ack2*pow(16,5);
            int ack3=(int)chaine[151];
            if(ack3>=97 && ack3<=102){
                ack3-=87;
            }else{
                ack3-='0';
            }
            ack3=ack3*pow(16,4);
            int ack4=(int)chaine[153];
            if(ack4>=97 && ack4<=102){
                ack4-=87;
            }else{
                ack4-='0';
            }
            ack4=ack4*pow(16,3);
            int ack5=(int)chaine[154];
            if(ack5>=97 && ack5<=102){
                ack5-=87;
            }else{
                ack5-='0';
            }
            ack5=ack5*pow(16,2);
            int ack6=(int)chaine[156];
            if(ack6>=97 && ack6<=102){
                ack6-=87;
            }else{
                ack6-='0';
            }
            ack6=ack6*pow(16,1);
            int ack7=(int)chaine[157];
            if(ack7>=97 && ack7<=102){
                ack7-=87;
            }else{
                ack7-='0';
            }
            ack7=ack7*pow(16,0);
            printf("    Acknowledgment Number: %d\n",ack0+ack1+ack2+ack3+ack4+ack5+ack6+ack7);
            fprintf(ecriture,"    Acknowledgment Number: %d\n",ack0+ack1+ack2+ack3+ack4+ack5+ack6+ack7);
            //Header Length
            int hlengthtcp=(int)chaine[159];
            if(hlengthtcp>=97 && hlengthtcp<=102){
                hlengthtcp-=87;
            }else{
                hlengthtcp-='0';
            }
            int lengthtcp=hlengthtcp;
            hlengthtcp=hlengthtcp*4;
            if(lengthtcp-8>=0){
                lengthtcp-=8;
                if(lengthtcp-4>=0){
                    lengthtcp-=4;
                    if(lengthtcp-2>=0){
                        lengthtcp-=2;
                        if(lengthtcp-1>=0){
                            lengthtcp-=1;
                            printf("    .... 1111 = Header Length: %d bytes (%c)\n",hlengthtcp,chaine[159]);
                            fprintf(ecriture,"    .... 1111 = Header Length: %d bytes (%c)\n",hlengthtcp,chaine[159]);
                        }else{
                            printf("    .... 1110 = Header Length: %d bytes (%c)\n",hlengthtcp,chaine[159]);
                            fprintf(ecriture,"    .... 1110 = Header Length: %d bytes (%c)\n",hlengthtcp,chaine[159]);
                        }
                    }else{
                        if(lengthtcp-1>=0){
                            lengthtcp-=1;
                            printf("    .... 1101 = Header Length: %d bytes (%c)\n",hlengthtcp,chaine[159]);
                            fprintf(ecriture,"    .... 1101 = Header Length: %d bytes (%c)\n",hlengthtcp,chaine[159]);
                        }else{
                            printf("    .... 1100 = Header Length: %d bytes (%c)\n",hlengthtcp,chaine[159]);
                            fprintf(ecriture,"    .... 1100 = Header Length: %d bytes (%c)\n",hlengthtcp,chaine[159]);
                        }
                    }
                }else{
                    if(lengthtcp-2>=0){
                        lengthtcp-=2;
                        if(lengthtcp-1>=0){
                            lengthtcp-=1;
                            printf("    .... 1011 = Header Length: %d bytes (%c)\n",hlengthtcp,chaine[159]);
                            fprintf(ecriture,"    .... 1011 = Header Length: %d bytes (%c)\n",hlengthtcp,chaine[159]);
                        }else{
                            printf("    .... 1010 = Header Length: %d bytes (%c)\n",hlengthtcp,chaine[159]);
                            fprintf(ecriture,"    .... 1010 = Header Length: %d bytes (%c)\n",hlengthtcp,chaine[159]);
                        }
                    }else{
                        if(lengthtcp-1>=0){
                            lengthtcp-=1;
                            printf("    .... 1001 = Header Length: %d bytes (%c)\n",hlengthtcp,chaine[159]);
                            fprintf(ecriture,"    .... 1001 = Header Length: %d bytes (%c)\n",hlengthtcp,chaine[159]);
                        }else{
                            printf("    .... 1000 = Header Length: %d bytes (%c)\n",hlengthtcp,chaine[159]);
                            fprintf(ecriture,"    .... 1000 = Header Length: %d bytes (%c)\n",hlengthtcp,chaine[159]);
                        }
                    }
                }
            }else{
                if(lengthtcp-4>=0){
                    lengthtcp-=4;
                    if(lengthtcp-2>=0){
                        lengthtcp-=2;
                        if(lengthtcp-1>=0){
                            lengthtcp-=1;
                            printf("    .... 0111 = Header Length: %d bytes (%c)\n",hlengthtcp,chaine[159]);
                            fprintf(ecriture,"    .... 0111 = Header Length: %d bytes (%c)\n",hlengthtcp,chaine[159]);
                        }else{
                            printf("    .... 0110 = Header Length: %d bytes (%c)\n",hlengthtcp,chaine[159]);
                            fprintf(ecriture,"    .... 0110 = Header Length: %d bytes (%c)\n",hlengthtcp,chaine[159]);
                        }
                    }else{
                        if(lengthtcp-1>=0){                
                            lengthtcp-=1;
                            printf("    .... 0101 = Header Length: %d bytes (%c)\n",hlengthtcp,chaine[159]);
                            fprintf(ecriture,"    .... 0101 = Header Length: %d bytes (%c)\n",hlengthtcp,chaine[159]);
                        }
                    }
                }
            }
            //Flags
            printf("    Flags: 0x%c%c%c\n",chaine[160],chaine[162],chaine[163]);
            fprintf(ecriture,"    Flags: 0x%c%c%c\n",chaine[160],chaine[162],chaine[163]);
            printf("        000. .... .... = Reserved: Not set\n");
            fputs("        000. .... .... = Reserved: Not set\n",ecriture);
            int f0=(int)chaine[160];
            if(f0>=97 && f0<=102){
                f0-=87;
            }else{
                f0-='0';
            }
            if(f0==1){
                printf("        ...1 .... .... = Nonce: Set\n");
                fputs("        ...1 .... .... = Nonce: Set\n",ecriture);
            }else{
                printf("        ...0 .... .... = Nonce: Not set\n");
                fputs("        ...0 .... .... = Nonce: Not set\n",ecriture);
            }
            int f1=(int)chaine[162];
            if(f1>=97 && f1<=102){
                f1-=87;
            }else{
                f1-='0';
            }
            if(f1-8>=0){
                f1-=8;
                printf("        .... 1... .... = Congestion Window Reduced (CWR): Set\n");
                fputs("        .... 1... .... = Congestion Window Reduced (CWR): Set\n",ecriture);
            }else{
                printf("        .... 0... .... = Congestion Window Reduced (CWR): Not set\n");
                fputs("        .... 0... .... = Congestion Window Reduced (CWR): Not set\n",ecriture);
            }
            if(f1-4>=0){
                f1-=4;
                printf("        .... .1.. .... = ECN-Echo: Set\n");
                fputs("        .... .1.. .... = ECN-Echo: Set\n",ecriture);
            }else{
                printf("        .... .0.. .... = ECN-Echo: Not set\n");
                fputs("        .... .0.. .... = ECN-Echo: Not set\n",ecriture);
            }
            if(f1-2>=0){
                f1-=2;
                printf("        .... ..1. .... = Urgent: Set\n");
                fputs("        .... ..1. .... = Urgent: Set\n",ecriture);
            }else{
                printf("        .... ..0. .... = Urgent: Not set\n");
                fputs("        .... ..0. .... = Urgent: Not set\n",ecriture);
            }
            if(f1-1>=0){
                f1-=1;
                printf("        .... ...1 .... = Acknowledgment: Set\n");
                fputs("        .... ...1 .... = Acknowledgment: Set\n",ecriture);
            }else{
                printf("        .... ...0 .... = Acknowledgment: Not set\n");
                fputs("        .... ...0 .... = Acknowledgment: Not set\n",ecriture);
            }
            int f2=(int)chaine[163];
            if(f2>=97 && f2<=102){
                f2-=87;
            }else{
                f2-='0';
            }
            if(f2-8>=0){
                f2-=8;
                printf("        .... .... 1... = Push: Set\n");
                fputs("        .... .... 1... = Push: Set\n",ecriture);
            }else{
                printf("        .... .... 0... = Push: Not set\n");
                fputs("        .... .... 0... = Push: Not set\n",ecriture);
            }
            if(f2-4>=0){
                f2-=4;
                printf("        .... .... .1.. = Reset: Set\n");
                fputs("        .... .... .1.. = Reset: Set\n",ecriture);
            }else{
                printf("        .... .... .0.. = Reset: Not set\n");
                fputs("        .... .... .0.. = Reset: Not set\n",ecriture);
            }
            if(f2-2>=0){
                f2-=2;
                printf("        .... .... ..1. = Syn: Set\n");
                fputs("        .... .... ..1. = Syn: Set\n",ecriture);
            }else{
                printf("        .... .... ..0. = Syn: Not set\n");
                fputs("        .... .... ..0. = Syn: Not set\n",ecriture);
            }
            if(f2-1>=0){
                f2-=1;
                printf("        .... .... ...1 = Fin: Set\n");
                fputs("        .... .... ...1 = Fin: Set\n",ecriture);
            }else{
                printf("        .... .... ...0 = Fin: Not set\n");
                fputs("        .... .... ...0 = Fin: Not set\n",ecriture);
            }
            //Window
            int w0=(int)chaine[172];
            if(w0>=97 && w0<=102){
                w0-=87;
            }else{
                w0-='0';
            }
            w0=w0*pow(16,3);
            int w1=(int)chaine[173];
            if(w1>=97 && w1<=102){
                w1-=87;
            }else{
                w1-='0';
            }
            w1=w1*pow(16,2);
            int w2=(int)chaine[175];
            if(w2>=97 && w2<=102){
                w2-=87;
            }else{
                w2-='0';
            }
            w2=w2*pow(16,1);
            int w3=(int)chaine[176];
            if(w3>=97 && w3<=102){
                w3-=87;
            }else{
                w3-='0';
            }
            w3=w3*pow(16,0);
            printf("    Window: %d\n",w0+w1+w2+w3);
            fprintf(ecriture,"    Window: %d\n",w0+w1+w2+w3);
            //Checksum
            printf("    Checksum: 0x%c%c%c%c\n",chaine[178],chaine[179],chaine[181],chaine[182]);
            fprintf(ecriture,"    Checksum: 0x%c%c%c%c\n",chaine[178],chaine[179],chaine[181],chaine[182]);
            //Urgent Pointer
            int up1=(int)chaine[162];
            if(up1>=97 && up1<=102){
                up1-=87;
            }else{
                up1-='0';
            }
            if(up1-2>=0){
                printf("    Urgent Pointer: 0x%c%c%c%c\n,",chaine[184],chaine[185],chaine[187],chaine[188]);
                fprintf(ecriture,"    Urgent Pointer: 0x%c%c%c%c\n,",chaine[184],chaine[185],chaine[187],chaine[188]);
            }else{
                printf("    Urgent Pointer: 0\n");
                fputs("    Urgent Pointer: 0\n",ecriture);
            }
            //Options
            int valuetcp=190;
            if(hlengthtcp>20){
                int optlengthtcp=20;
                printf("    Options: (%d bytes)\n",hlengthtcp-optlengthtcp);
                fprintf(ecriture,"    Options: (%d bytes)\n",hlengthtcp-optlengthtcp);
                while(hlengthtcp>optlengthtcp){
                    int opttcp0=(int)chaine[valuetcp];
                    int opttcp1=(int)chaine[valuetcp+1];
                    if(opttcp0>=97 && opttcp0<=102){
                        opttcp0-=87;
                    }else{
                        opttcp0-='0';
                    }
                    opttcp0=opttcp0*pow(16,1);
                    if(opttcp1>=97 && opttcp1<=102){
                        opttcp1-=87;
                    }else{
                        opttcp1-='0';
                    }
                    opttcp1=opttcp1*pow(16,0);
                    if(opttcp0+opttcp1==0){
                        printf("        TCP Option - End of Option List (EOL)\n");
                        fputs("        TCP Option - End of Option List (EOL)\n",ecriture);
                        printf("            Kind: End of Option List (0)\n");
                        fputs("            Kind: End of Option List (0)\n",ecriture);
                        optlengthtcp++;
                        if(chaine[valuetcp+2]=='\n'){
                            valuetcp+=10;
                        }else{
                            valuetcp+=3;
                        }
                    }if(opttcp0+opttcp1==1){
                        printf("        TCP Option - No-Operation (NOP)\n");
                        fputs("        TCP Option - No-Operation (NOP)\n",ecriture);
                        printf("            Kind: No-Operation (1)\n");
                        fputs("            Kind: No-Operation (1)\n",ecriture);
                        optlengthtcp++;
                        if(chaine[valuetcp+2]=='\n'){
                            valuetcp+=10;
                        }else{
                            valuetcp+=3;
                        }
                    }if(opttcp0+opttcp1==2){
                        printf("        TCP Option - Maximum segment size\n");
                        fputs("        TCP Option - Maximum segment size\n",ecriture);
                        printf("            Kind: Maximum Segment Size (2)\n");
                        fputs("            Kind: Maximum Segment Size (2)\n",ecriture);
                        printf("            Length: 4\n");
                        fputs("            Length: 4\n",ecriture);
                        if(chaine[valuetcp+2]!='\n' && chaine[valuetcp+5]!='\n' && chaine[valuetcp+8]!='\n'){
                            int mssvalue0=(int)chaine[valuetcp+6];
                            if(mssvalue0>=97 && mssvalue0<=102){
                                mssvalue0-=87;
                            }else{
                                mssvalue0-='0';
                            }
                            mssvalue0=mssvalue0*pow(16,3);
                            int mssvalue1=(int)chaine[valuetcp+7];
                            if(mssvalue1>=97 && mssvalue1<=102){
                                mssvalue1-=87;
                            }else{
                                mssvalue1-='0';
                            }
                            mssvalue1=mssvalue1*pow(16,2);
                            int mssvalue2=(int)chaine[valuetcp+9];
                            if(mssvalue2>=97 && mssvalue2<=102){
                                mssvalue2-=87;
                            }else{
                                mssvalue2-='0';
                            }
                            mssvalue2=mssvalue2*pow(16,1);
                            int mssvalue3=(int)chaine[valuetcp+10];
                            if(mssvalue3>=97 && mssvalue3<=102){
                                mssvalue3-=87;
                            }else{
                                mssvalue3-='0';
                            }
                            mssvalue3=mssvalue3*pow(16,0);
                            printf("            MSS Value: %d\n",mssvalue0+mssvalue1+mssvalue2+mssvalue3);
                            fprintf(ecriture,"            MSS Value: %d\n",mssvalue0+mssvalue1+mssvalue2+mssvalue3);
                            optlengthtcp=optlengthtcp+4;
                            valuetcp+=12;
                        }else{
                            if(chaine[valuetcp+2]=='\n' || chaine[valuetcp+5]=='\n'){
                                int mssvalue0=(int)chaine[valuetcp+13];
                                if(mssvalue0>=97 && mssvalue0<=102){
                                    mssvalue0-=87;
                                }else{
                                    mssvalue0-='0';
                                }
                                mssvalue0=mssvalue0*pow(16,3);
                                int mssvalue1=(int)chaine[valuetcp+14];
                                if(mssvalue1>=97 && mssvalue1<=102){
                                    mssvalue1-=87;
                                }else{
                                    mssvalue1-='0';
                                }
                                mssvalue1=mssvalue1*pow(16,2);
                                int mssvalue2=(int)chaine[valuetcp+16];
                                if(mssvalue2>=97 && mssvalue2<=102){
                                    mssvalue2-=87;
                                }else{
                                    mssvalue2-='0';
                                }
                                mssvalue2=mssvalue2*pow(16,1);
                                int mssvalue3=(int)chaine[valuetcp+17];
                                if(mssvalue3>=97 && mssvalue3<=102){
                                    mssvalue3-=87;
                                }else{
                                    mssvalue3-='0';
                                }
                                mssvalue3=mssvalue3*pow(16,0);
                                printf("            MSS Value: %d\n",mssvalue0+mssvalue1+mssvalue2+mssvalue3);
                                fprintf(ecriture,"            MSS Value: %d\n",mssvalue0+mssvalue1+mssvalue2+mssvalue3);
                                optlengthtcp=optlengthtcp+4;
                                valuetcp+=19;
                            }
                            if(chaine[valuetcp+8]=='\n'){
                                int mssvalue0=(int)chaine[valuetcp+6];
                                if(mssvalue0>=97 && mssvalue0<=102){
                                    mssvalue0-=87;
                                }else{
                                    mssvalue0-='0';
                                }
                                mssvalue0=mssvalue0*pow(16,3);
                                int mssvalue1=(int)chaine[valuetcp+7];
                                if(mssvalue1>=97 && mssvalue1<=102){
                                    mssvalue1-=87;
                                }else{
                                    mssvalue1-='0';
                                }
                                mssvalue1=mssvalue1*pow(16,2);
                                int mssvalue2=(int)chaine[valuetcp+16];
                                if(mssvalue2>=97 && mssvalue2<=102){
                                    mssvalue2-=87;
                                }else{
                                    mssvalue2-='0';
                                }
                                mssvalue2=mssvalue2*pow(16,1);
                                int mssvalue3=(int)chaine[valuetcp+17];
                                if(mssvalue3>=97 && mssvalue3<=102){
                                    mssvalue3-=87;
                                }else{
                                    mssvalue3-='0';
                                }
                                mssvalue3=mssvalue3*pow(16,0);
                                printf("            MSS Value: %d\n",mssvalue0+mssvalue1+mssvalue2+mssvalue3);
                                fprintf(ecriture,"            MSS Value: %d\n",mssvalue0+mssvalue1+mssvalue2+mssvalue3);
                                optlengthtcp=optlengthtcp+4;
                                valuetcp+=19;
                            }
                        }
                    }if(opttcp0+opttcp1==3){
                        printf("        TCP Option - Window scale\n");
                        fputs("        TCP Option - Window scale\n",ecriture);
                        printf("            Kind: Window scale (3)\n");
                        fputs("            Kind: Window scale (3)\n",ecriture);
                        printf("            Length: 3\n");
                        fputs("            Length: 3\n",ecriture);
                        if(chaine[valuetcp+2]!='\n' && chaine[valuetcp+5]!='\n'){
                            int s0=(int)chaine[valuetcp+6];
                            if(s0>=97 && s0<=102){
                                s0-=87;
                            }else{
                                s0-='0';
                            }
                            s0=s0*pow(16,1);
                            int s1=(int)chaine[valuetcp+7];
                            if(s1>=97 && s1<=102){
                                s1-=87;
                            }else{
                                s1-='0';
                            }
                            s1=s1*pow(16,0);
                            printf("            Shift count: %d\n",s0+s1);
                            fprintf(ecriture,"            Shift count: %d\n",s0+s1);
                            optlengthtcp=optlengthtcp+3;
                            valuetcp+=9;
                        }else{
                            int s0=(int)chaine[valuetcp+13];
                            if(s0>=97 && s0<=102){
                                s0-=87;
                            }else{
                                s0-='0';
                            }
                            s0=s0*pow(16,1);
                            int s1=(int)chaine[valuetcp+14];
                            if(s1>=97 && s1<=102){
                                s1-=87;
                            }else{
                                s1-='0';
                            }
                            s1=s1*pow(16,0);
                            printf("            Shift count: %d\n",s0+s1);
                            fprintf(ecriture,"            Shift count: %d\n",s0+s1);
                            optlengthtcp=optlengthtcp+3;
                            valuetcp+=16;
                        }
                    }if(opttcp0+opttcp1==4){
                        printf("        TCP Option - SACK permitted\n");
                        fputs("        TCP Option - SACK permitted\n",ecriture);
                        printf("            Kind: SACK permitted (4)\n");
                        fputs("            Kind: SACK permitted (4)\n",ecriture);
                        printf("            Length: 2\n");
                        fputs("            Length: 2\n",ecriture);
                        optlengthtcp=optlengthtcp+2;
                        if(chaine[valuetcp+2]=='\n' || chaine[valuetcp+5]=='\n'){
                            valuetcp+=13;
                        }else{
                            valuetcp+=6;
                        }
                    }if(opttcp0+opttcp1==8){
                        printf("        TCP Option - Timestamps\n");
                        fputs("        TCP Option - Timestamps\n",ecriture);
                        printf("            Kind: Time Stamp Option (8)\n");
                        fputs("            Kind: Time Stamp Option (8)\n",ecriture);
                        printf("            Length: 10\n");
                        fputs("            Length: 10\n",ecriture);
                        if(chaine[valuetcp+2]=='\n' || chaine[valuetcp+5]=='\n'){
                            valuetcp+=13;
                        }else{
                            valuetcp+=6;
                        }
                        int timev0,timev1,timev2,timev3,timev4,timev5,timev6,timev7;
                        timev0=(int)chaine[valuetcp];
                        if(timev0>=97 && timev0<=102){
                            timev0-=87;
                        }else{
                            timev0-='0';
                        }
                        timev0=timev0*pow(16,7);
                        timev1=(int)chaine[valuetcp+1];
                        if(timev1>=97 && timev1<=102){
                            timev1-=87;
                        }else{
                            timev1-='0';
                        }
                        timev1=timev1*pow(16,6);
                        if(chaine[valuetcp+2]!='\n'){
                            timev2=(int)chaine[valuetcp+3];
                            if(timev2>=97 && timev2<=102){
                                timev2-=87;
                            }else{
                                timev2-='0';
                            }
                            timev2=timev2*pow(16,5);
                            timev3=(int)chaine[valuetcp+4];
                            if(timev3>=97 && timev3<=102){
                                timev3-=87;
                            }else{
                                timev3-='0';
                            }
                            timev3=timev3*pow(16,4);
                            if(chaine[valuetcp+5]!='\n'){
                                timev4=(int)chaine[valuetcp+6];
                                if(timev4>=97 && timev4<=102){
                                    timev4-=87;
                                }else{
                                    timev4-='0';
                                }
                                timev4=timev4*pow(16,3);
                                timev5=(int)chaine[valuetcp+7];
                                if(timev5>=97 && timev5<=102){
                                    timev5-=87;
                                }else{
                                    timev5-='0';
                                }
                                timev5=timev5*pow(16,2);
                                if(chaine[valuetcp+8]!='\n'){
                                    timev6=(int)chaine[valuetcp+9];
                                    if(timev6>=97 && timev6<=102){
                                        timev6-=87;
                                    }else{
                                        timev6-='0';
                                    }
                                    timev6=timev6*pow(16,1);
                                    timev7=(int)chaine[valuetcp+10];
                                    if(timev7>=97 && timev7<=102){
                                        timev7-=87;
                                    }else{
                                        timev7-='0';
                                    }
                                    timev7=timev7*pow(16,0);
                                    if(chaine[valuetcp+11]!='\n'){
                                        valuetcp+=12;
                                    }else{
                                        valuetcp+=19;
                                    }
                                }else{
                                    timev6=(int)chaine[valuetcp+16];
                                    if(timev6>=97 && timev2<=102){
                                        timev6-=87;
                                    }else{
                                        timev6-='0';
                                    }
                                    timev6=timev6*pow(16,1);
                                    timev7=(int)chaine[valuetcp+17];
                                    if(timev7>=97 && timev7<=102){
                                        timev7-=87;
                                    }else{
                                        timev7-='0';
                                    }
                                    timev7=timev7*pow(16,0);
                                    valuetcp+=19;
                                }
                            }else{
                                timev4=(int)chaine[valuetcp+13];
                                if(timev4>=97 && timev4<=102){
                                    timev4-=87;
                                }else{
                                    timev4-='0';
                                }
                                timev4=timev4*pow(16,3);
                                timev5=(int)chaine[valuetcp+14];
                                if(timev5>=97 && timev5<=102){
                                    timev5-=87;
                                }else{
                                    timev5-='0';
                                }
                                timev5=timev5*pow(16,2);
                                timev6=(int)chaine[valuetcp+16];
                                if(timev6>=97 && timev6<=102){
                                    timev6-=87;
                                }else{
                                    timev6-='0';
                                }
                                timev6=timev6*pow(16,1);
                                timev7=(int)chaine[valuetcp+17];
                                if(timev7>=97 && timev7<=102){
                                    timev7-=87;
                                }else{
                                    timev7-='0';
                                }
                                timev7=timev7*pow(16,0);
                                valuetcp+=19;
                            }
                        }else{
                            timev2=(int)chaine[valuetcp+10];
                            if(timev2>=97 && timev2<=102){
                                timev2-=87;
                            }else{
                                timev2-='0';
                            }
                            timev2=timev2*pow(16,5);
                            timev3=(int)chaine[valuetcp+11];
                            if(timev3>=97 && timev3<=102){
                                timev3-=87;
                            }else{
                                timev3-='0';
                            }
                            timev3=timev3*pow(16,4);
                            timev4=(int)chaine[valuetcp+13];
                            if(timev4>=97 && timev4<=102){
                                timev4-=87;
                            }else{
                                timev4-='0';
                            }
                            timev4=timev4*pow(16,3);
                            timev5=(int)chaine[valuetcp+14];
                            if(timev5>=97 && timev5<=102){
                                timev5-=87;
                            }else{
                                timev5-='0';
                            }
                            timev5=timev5*pow(16,2);
                            timev6=(int)chaine[valuetcp+16];
                            if(timev6>=97 && timev6<=102){
                                timev6-=87;
                            }else{
                                timev6-='0';
                            }
                            timev6=timev6*pow(16,1);
                            timev7=(int)chaine[valuetcp+17];
                            if(timev7>=97 && timev7<=102){
                                timev7-=87;
                            }else{
                                timev7-='0';
                            }
                            timev7=timev7*pow(16,0);
                            valuetcp+=19;
                        }printf("        Timestamp value: %d\n",timev0+timev1+timev2+timev3+timev4+timev5+timev6+timev7);
                        fprintf(ecriture,"        Timestamp value: %d\n",timev0+timev1+timev2+timev3+timev4+timev5+timev6+timev7);
                        int timeechor0,timeechor1,timeechor2,timeechor3,timeechor4,timeechor5,timeechor6,timeechor7;
                        timeechor0=(int)chaine[valuetcp];
                        if(timeechor0>=97 && timeechor0<=102){
                            timeechor0-=87;
                        }else{
                            timeechor0-='0';
                        }
                        timeechor0=timeechor0*pow(16,7);
                        timeechor1=(int)chaine[valuetcp+1];
                        if(timeechor1>=97 && timeechor1<=102){
                            timeechor1-=87;
                        }else{
                            timeechor1-='0';
                        }
                        timeechor1=timeechor1*pow(16,6);
                        if(chaine[valuetcp+2]!='\n'){
                            timeechor2=(int)chaine[valuetcp+3];
                            if(timeechor2>=97 && timeechor2<=102){
                                timeechor2-=87;
                            }else{
                                timeechor2-='0';
                            }
                            timeechor2=timeechor2*pow(16,5);
                            timeechor3=(int)chaine[valuetcp+4];
                            if(timeechor3>=97 && timeechor3<=102){
                                timeechor3-=87;
                            }else{
                                timeechor3-='0';
                            }
                            timeechor3=timeechor3*pow(16,4);
                            if(chaine[valuetcp+5]!='\n'){
                                timeechor4=(int)chaine[valuetcp+6];
                                if(timeechor4>=97 && timeechor4<=102){
                                    timeechor4-=87;
                                }else{
                                    timeechor4-='0';
                                }
                                timeechor4=timeechor4*pow(16,3);
                                timeechor5=(int)chaine[valuetcp+7];
                                if(timeechor5>=97 && timeechor5<=102){
                                    timeechor5-=87;
                                }else{
                                    timeechor5-='0';
                                }
                                timeechor5=timeechor5*pow(16,2);
                                if(chaine[valuetcp+8]!='\n'){
                                    timeechor6=(int)chaine[valuetcp+9];
                                    if(timeechor6>=97 && timeechor6<=102){
                                        timeechor6-=87;
                                    }else{
                                        timeechor6-='0';
                                    }
                                    timeechor6=timeechor6*pow(16,1);
                                    timeechor7=(int)chaine[valuetcp+10];
                                    if(timeechor7>=97 && timeechor7<=102){
                                        timeechor7-=87;
                                    }else{
                                        timeechor7-='0';
                                    }
                                    timeechor7=timeechor7*pow(16,0);
                                    if(chaine[valuetcp+11]!='\n'){
                                        valuetcp+=12;
                                    }else{
                                        valuetcp+=19;
                                    }
                                }else{
                                    timeechor6=(int)chaine[valuetcp+16];
                                    if(timeechor6>=97 && timeechor2<=102){
                                        timeechor6-=87;
                                    }else{
                                        timeechor6-='0';
                                    }
                                    timeechor6=timeechor6*pow(16,1);
                                    timeechor7=(int)chaine[valuetcp+17];
                                    if(timeechor7>=97 && timeechor7<=102){
                                        timeechor7-=87;
                                    }else{
                                        timeechor7-='0';
                                    }
                                    timeechor7=timeechor7*pow(16,0);
                                    valuetcp+=19;
                                }
                            }else{
                                timeechor4=(int)chaine[valuetcp+13];
                                if(timeechor4>=97 && timeechor4<=102){
                                    timeechor4-=87;
                                }else{
                                    timeechor4-='0';
                                }
                                timeechor4=timeechor4*pow(16,3);
                                timeechor5=(int)chaine[valuetcp+14];
                                if(timeechor5>=97 && timeechor5<=102){
                                    timeechor5-=87;
                                }else{
                                    timeechor5-='0';
                                }
                                timeechor5=timeechor5*pow(16,2);
                                timeechor6=(int)chaine[valuetcp+16];
                                if(timeechor6>=97 && timeechor6<=102){
                                    timeechor6-=87;
                                }else{
                                    timeechor6-='0';
                                }
                                timeechor6=timeechor6*pow(16,1);
                                timeechor7=(int)chaine[valuetcp+17];
                                if(timeechor7>=97 && timeechor7<=102){
                                    timeechor7-=87;
                                }else{
                                    timeechor7-='0';
                                }
                                timeechor7=timeechor7*pow(16,0);
                                valuetcp+=19;
                            }
                        }else{
                            timeechor2=(int)chaine[valuetcp+10];
                            if(timeechor2>=97 && timeechor2<=102){
                                timeechor2-=87;
                            }else{
                                timeechor2-='0';
                            }
                            timeechor2=timeechor2*pow(16,5);
                            timeechor3=(int)chaine[valuetcp+11];
                            if(timeechor3>=97 && timeechor3<=102){
                                timeechor3-=87;
                            }else{
                                timeechor3-='0';
                            }
                            timeechor3=timeechor3*pow(16,4);
                            timeechor4=(int)chaine[valuetcp+13];
                            if(timeechor4>=97 && timeechor4<=102){
                                timeechor4-=87;
                            }else{
                                timeechor4-='0';
                            }
                            timeechor4=timeechor4*pow(16,3);
                            timeechor5=(int)chaine[valuetcp+14];
                            if(timeechor5>=97 && timeechor5<=102){
                                timeechor5-=87;
                            }else{
                                timeechor5-='0';
                            }
                            timeechor5=timeechor5*pow(16,2);
                            timeechor6=(int)chaine[valuetcp+16];
                            if(timeechor6>=97 && timeechor6<=102){
                                timeechor6-=87;
                            }else{
                                timeechor6-='0';
                            }
                            timeechor6=timeechor6*pow(16,1);
                            timeechor7=(int)chaine[valuetcp+17];
                            if(timeechor7>=97 && timeechor7<=102){
                                timeechor7-=87;
                            }else{
                                timeechor7-='0';
                            }
                            timeechor7=timev7*pow(16,0);
                            valuetcp+=19;
                        }printf("        Timestamp echo reply: %d\n",timeechor0+timeechor1+timeechor2+timeechor3+timeechor4+timeechor5+timeechor6+timeechor7);
                        fprintf(ecriture,"        Timestamp echo reply: %d\n",timeechor0+timeechor1+timeechor2+timeechor3+timeechor4+timeechor5+timeechor6+timeechor7);
                        optlengthtcp=optlengthtcp+10;
                    }
                }
            }
            //HTTP
            int test0=(int)chaine[valuetcp];
            if(test0>=97 && test0<=102){
                test0-=87;
            }else{
                test0-='0';
            }
            test0=test0*pow(16,1);
            int test1=(int)chaine[valuetcp+1];
            if(test1>=97 && test1<=102){
                test1-=87;
            }else{
                test1-='0';
            }
            test1=test1*pow(16,0);
            if((chaine[valuetcp]!='\0') && ((test0+test1)>=65 && (test0+test1)<=90)){
                printf("Hypertext Transfer Protocol\n");
                fputs("Hypertext Transfer Protocol\n",ecriture);
                char http[3];
                int ind0=valuetcp;
                int ind1=valuetcp+1;
                http[0]=chaine[ind0];
                http[1]=chaine[ind1];
                char next0[3]="0d";
                char next1[3]="0a";
                char comp[3];
                int comp0;
                int comp1;
                while(1){
                    comp0=ind0;
                    comp1=ind1;
                    comp[0]=chaine[comp0];
                    comp[1]=chaine[comp1];
                    if(strcmp(comp,next0)==0){
                        if(chaine[comp1+1]=='\n'){
                            comp0=comp0+10;
                            comp1=comp1+10;
                            comp[0]=chaine[comp0];
                            comp[1]=chaine[comp1];
                        }else{
                            comp0=comp0+3;
                            comp1=comp1+3;
                            comp[0]=chaine[comp0];
                            comp[1]=chaine[comp1];
                        }
                        if(strcmp(comp,next1)==0){
                            if(chaine[comp1+1]=='\n'){
                                comp0=comp0+10;
                                comp1=comp1+10;
                                comp[0]=chaine[comp0];
                                comp[1]=chaine[comp1];
                            }else{
                                comp0=comp0+3;
                                comp1=comp1+3;
                                comp[0]=chaine[comp0];
                                comp[1]=chaine[comp1];
                            }
                            if(strcmp(comp,next0)==0){
                                if(chaine[comp1+1]=='\n'){
                                    comp0=comp0+10;
                                    comp1=comp1+10;
                                    comp[0]=chaine[comp0];
                                    comp[1]=chaine[comp1];
                                }else{
                                    comp0=comp0+3;
                                    comp1=comp1+3;
                                    comp[0]=chaine[comp0];
                                    comp[1]=chaine[comp1];
                                }
                                if(strcmp(comp,next1)==0){
                                    break;
                                }
                            }
                        }
                    }
                    int http0=(int)http[0];
                    if(http0>=97 && http0<=102){
                        http0-=87;
                    }else{
                        http0-='0';
                    }
                    http0=http0*pow(16,1);
                    int http1=(int)http[1];
                    if(http1>=97 && http1<=102){
                        http1-=87;
                    }else{
                        http1-='0';
                    }
                    http1=http1*pow(16,0);
                    printf("%c",http0+http1);
                    fprintf(ecriture,"%c",http0+http1);
                    if(chaine[ind1+1]=='\n'){
                        ind0=ind0+10;
                        ind1=ind1+10;
                        http[0]=chaine[ind0];
                        http[1]=chaine[ind1];
                    }else{
                        ind0=ind0+3;
                        ind1=ind1+3;
                        http[0]=chaine[ind0];
                        http[1]=chaine[ind1];
                    }
                }
            }
        }
    }else{
        printf("Le fichier n'existe pas");
    }
    fclose(fichier);
    fclose(ecriture);
    return 0;
}