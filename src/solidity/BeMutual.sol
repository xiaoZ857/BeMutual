pragma solidity ^0.8.0;

contract BeMutual{

    struct IPData{
        int IP;
        address owner;
    }

    mapping (address => IPData) BCADDtoIP;

    function Create(address _BCADD, int _IP)public returns(bool){

        bool existed = (BCADDtoIP[_BCADD].owner != address(0));

        if(existed==false){
            BCADDtoIP[_BCADD].IP = _IP;
            BCADDtoIP[_BCADD].owner = msg.sender;
        }
        return existed;
    }

    function Update(address _BCADD, int _IP)public returns(bool){

        bool eligible = (BCADDtoIP[_BCADD].owner == msg.sender);

        if(eligible){
            BCADDtoIP[_BCADD].IP = _IP;
        }
        return eligible;
    }

    function Verification(address _BCADD, int _IP) public view returns (bool){

        bool check = (BCADDtoIP[_BCADD].IP == _IP);
        return check;
    }

    function Search(address _BCADD)public view returns(int){

        return BCADDtoIP[_BCADD].IP;

    }

    function State(address _BCADD)public view returns(bool, bool, bool){

        bool bonded = (BCADDtoIP[_BCADD].IP != 0);

        bool existed = (BCADDtoIP[_BCADD].owner != address(0));

        bool eligible = (BCADDtoIP[_BCADD].owner == msg.sender);

        return (bonded, existed, eligible);
    }
}
